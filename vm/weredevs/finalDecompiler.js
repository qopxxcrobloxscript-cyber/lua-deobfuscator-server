// vm/weredevs/finalDecompiler.js
'use strict';

// ════════════════════════════════════════════════════════════════════════
//  weredevFinalDecompile — Weredevs VM 最終解読エンジン
//
//  パイプライン:
//    Step 1: 数値エスケープ文字列デコード  "\072\048\083" → "H0S"
//    Step 2: Base64 文字列インライン展開
//    Step 3: VM bytecode 解析 → execution trace 構築
//    Step 4: while J do ... end (VM interpreter) を Lua コードに変換
//    Step 5: VM interpreter ブロックを削除し、通常の Lua コードを出力
// ════════════════════════════════════════════════════════════════════════

const { LUA51_OPCODES, assignWeredevOpcodes,
        _inferOpNameFromOperands, vmDecompileInstruction,
        resolveInstrConstants }        = require('./opcodeMap');
const { extractWeredevConstPool,
        extractWeredevZAccessor,
        extractWeredevDispatchLoop }   = require('./extractor');
const { detectWeredevContext,
        analyzeWeredevOpcodeBlock,
        extractWeredevOperands,
        _buildFlatConstPool,
        resolveWeredevZCalls }         = require('./interpreterParser');
const { emulateWeredevVM }            = require('./emulator');

// ════════════════════════════════════════════════════════════════════════
//  Step 1: 数値エスケープ文字列デコード
//  "\072\048\083" → "H0S"
// ════════════════════════════════════════════════════════════════════════
function decodeNumericEscapes(code) {
  if (!code) return { code, count: 0 };
  let count = 0;

  const processStr = (inner) => {
    if (!/\\[0-9]/.test(inner) && !/\\x[0-9a-fA-F]/i.test(inner)) return null;
    const decoded = _unescapeLuaEscapes(inner);
    if (decoded === inner) return null;
    if ([...decoded].some(c => { const n = c.charCodeAt(0); return n < 0x09 || (n > 0x0d && n < 0x20); })) return null;
    count++;
    return `"${_escapeLuaStr(decoded)}"`;
  };

  let result = code.replace(/"((?:[^"\\]|\\[\s\S])*)"/g, (match, inner) => processStr(inner) || match);
  result = result.replace(/'((?:[^'\\]|\\[\s\S])*)'/g,   (match, inner) => processStr(inner) || match);
  return { code: result, count };
}

function _unescapeLuaEscapes(s) {
  let out = '', i = 0;
  while (i < s.length) {
    if (s[i] !== '\\' || i + 1 >= s.length) { out += s[i++]; continue; }
    const next = s[i + 1];
    if ((next === 'x' || next === 'X') && i + 3 < s.length) {
      const h = s.substring(i + 2, i + 4);
      if (/^[0-9a-fA-F]{2}$/.test(h)) { out += String.fromCharCode(parseInt(h, 16)); i += 4; continue; }
    }
    if (/[0-9]/.test(next)) {
      let num = '', j = i + 1;
      while (j < s.length && j < i + 4 && /[0-9]/.test(s[j])) { num += s[j]; j++; }
      const n = parseInt(num, 10);
      if (n <= 255) { out += String.fromCharCode(n); i = j; continue; }
    }
    const ESC = { n:'\n', t:'\t', r:'\r', '\\':'\\', '"':'"', "'":"'", '0':'\0', a:'\x07', b:'\x08', f:'\x0c', v:'\x0b' };
    if (ESC[next] !== undefined) { out += ESC[next]; i += 2; continue; }
    out += s[i] + s[i + 1]; i += 2;
  }
  return out;
}

function _escapeLuaStr(s) {
  return s.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n').replace(/\r/g,'\\r').replace(/\0/g,'\\0');
}

// ════════════════════════════════════════════════════════════════════════
//  Step 2: Base64 文字列インライン展開
// ════════════════════════════════════════════════════════════════════════
function decodeBase64Strings(code) {
  if (!code) return { code, count: 0 };
  let count = 0;
  const result = code.replace(/"([A-Za-z0-9+\/]{16,}={0,2})"/g, (match, b64) => {
    try {
      const decoded = Buffer.from(b64, 'base64').toString('utf8');
      const ok = [...decoded].every(c => {
        const n = c.charCodeAt(0);
        return (n >= 0x20 && n <= 0x7e) || n === 0x0a || n === 0x0d || n === 0x09;
      });
      if (ok && decoded.length > 0) { count++; return `"${_escapeLuaStr(decoded)}"`; }
    } catch {}
    return match;
  });
  return { code: result, count };
}

// ════════════════════════════════════════════════════════════════════════
//  Step 3: VM bytecode 解析 → execution trace 構築
//
//  ── 核心的な修正 ──
//  _extractIfChain で各 if/elseif ブロックの本体を「自分のブロックだけ」
//  正確に切り出せるよう、境界検出を完全に書き直した。
//
//  アルゴリズム:
//    1. while J do ... end 全体を _findWhileEnd で取り出す
//    2. ブロック本体を _sliceIfChain でトークン走査して分割
//       → 各 elseif/else の直前位置で切断する
//    3. 各スライスを opcodeBlock として返す
// ════════════════════════════════════════════════════════════════════════
function buildExecutionTrace(code) {
  const constPools = extractWeredevConstPool(code);
  const accessors  = extractWeredevZAccessor(code, constPools);
  const ctx        = detectWeredevContext(code);

  const accList = Object.values(accessors);
  if (accList.length > 0) { ctx.poolVar = accList[0].poolName; ctx.zFunc = accList[0].funcName; }

  const dispatchLoops = _extractDispatchLoopsV2(code, ctx);
  const bestLoop = dispatchLoops.length > 0
    ? dispatchLoops.reduce((a, b) => b.blockCount > a.blockCount ? b : a)
    : null;

  if (!bestLoop) {
    // fallback
    const fbLoops = extractWeredevDispatchLoop(code);
    if (fbLoops.length === 0) return { trace:[], opcodeBlocks:[], constPools, accessors, ctx, dispatchLoops:[] };
    const fb = fbLoops.reduce((a, b) => b.blockCount > a.blockCount ? b : a);
    return _buildTraceFromLoop(fb, constPools, accessors, ctx, fbLoops);
  }
  return _buildTraceFromLoop(bestLoop, constPools, accessors, ctx, dispatchLoops);
}

// ── while ループの検出 (token-level depth counting) ─────────────────────
function _extractDispatchLoopsV2(code, ctx) {
  const loops   = [];
  const loopVar = ctx.loopVar || 'J';

  // while <loopVar> do
  const whileRe = new RegExp(`\\bwhile\\s+${_reEsc(loopVar)}\\s+do\\b`, 'g');
  let m;
  while ((m = whileRe.exec(code)) !== null) {
    const bodyStart = m.index + m[0].length;
    const endIdx    = _findWhileBodyEnd(code, bodyStart);
    if (endIdx === -1) continue;

    const loopBody       = code.substring(bodyStart, endIdx);
    const dispatchBlocks = _sliceIfChain(loopBody, loopVar);
    if (dispatchBlocks.length < 1) continue;

    let loopEnd = endIdx + 3; // skip 'end'
    while (loopEnd < code.length && (code[loopEnd] === '\n' || code[loopEnd] === '\r')) loopEnd++;

    loops.push({ loopVar, loopStart: m.index, loopEnd, body: loopBody, dispatchBlocks, blockCount: dispatchBlocks.length });
  }

  // while true do (loopVar を if-chain から推定)
  const wtRe = /\bwhile\s+true\s+do\b/g;
  while ((m = wtRe.exec(code)) !== null) {
    const bodyStart = m.index + m[0].length;
    const endIdx    = _findWhileBodyEnd(code, bodyStart);
    if (endIdx === -1) continue;
    const loopBody    = code.substring(bodyStart, endIdx);
    const detectedVar = _detectLoopVar(loopBody) || loopVar;
    const dispatchBlocks = _sliceIfChain(loopBody, detectedVar);
    if (dispatchBlocks.length < 2) continue;
    let loopEnd = endIdx + 3;
    while (loopEnd < code.length && (code[loopEnd] === '\n' || code[loopEnd] === '\r')) loopEnd++;
    loops.push({ loopVar: detectedVar, loopStart: m.index, loopEnd, body: loopBody, dispatchBlocks, blockCount: dispatchBlocks.length, isWhileTrue: true });
  }

  return loops;
}

/**
 * while...do の直後から対応する end の直前位置を返す。
 * token-level depth counting: if/while/for/function/repeat → depth++
 *                              end/until                   → depth--
 * do/then は **カウントしない** (while/for/if がすでにカウント済み)
 */
function _findWhileBodyEnd(code, start) {
  const re = /\b(if|while|for|repeat|function)\b|\bend\b|\buntil\b/g;
  re.lastIndex = start;
  let depth = 1, m;
  while ((m = re.exec(code)) !== null) {
    const kw = m[0];
    if (/^(if|while|for|repeat|function)$/.test(kw)) depth++;
    else if (kw === 'end' || kw === 'until') { depth--; if (depth === 0) return m.index; }
  }
  return -1;
}

/**
 * loopBody (while...do と end の間) を
 * if J < N then / elseif J < N then / else ... end の構造で分割する。
 *
 * 実装方針:
 *   - depth=0 の if/elseif/else/end をブランチ境界として収集する
 *   - 「if」の後は depth=1 になるが、elseif/else/end は depth を
 *     一旦 1→0 に戻す（同一 if-chain の分岐として扱う）ため、
 *     走査を「同一 if-chain の end を探す」ロジックで実装する
 */
function _sliceIfChain(loopBody, loopVar) {
  const lv = _reEsc(loopVar);

  // ── Phase 1: トップレベルの if-chain を1つ見つける ─────────────────
  // loopBody の先頭にある "if <loopVar> < N then" を探す
  const firstIfRe = new RegExp(`\\bif\\s+${lv}\\s*(<|<=|==)\\s*(\\d+)\\s*then`);
  const firstM    = firstIfRe.exec(loopBody);
  if (!firstM) return [];

  // ── Phase 2: if-chain 全体 (if...end) を境界ごとにスライス ────────
  // "if" に対応する "end" をトークン走査で探す
  // if/while/for/function/repeat → depth++  |  end/until → depth--
  // ただし elseif/else は depth を変化させない（if と同じブロック内）
  const headers = [];  // { kind, index, matchEnd, threshold?, op? }

  const scanRe = /\b(if|elseif|else|end|while|for|repeat|function|until)\b/g;
  scanRe.lastIndex = firstM.index;
  let depth = 0;
  let sm;

  while ((sm = scanRe.exec(loopBody)) !== null) {
    const kw = sm[1];

    if (kw === 'if') {
      depth++;
      if (depth === 1) {
        // トップレベルの if
        const rest   = loopBody.substring(sm.index + 2);
        const condM  = rest.match(/^\s+([A-Za-z_]\w*)\s*(<|<=|==)\s*(\d+)\s*then/);
        if (condM) {
          headers.push({ kind: 'if', index: sm.index, matchEnd: sm.index + 2 + condM[0].length, threshold: parseInt(condM[3]), op: condM[2] });
        } else {
          depth--; // 閾値パターンに一致しない if はカウントしない
        }
      }
    } else if (kw === 'elseif' && depth === 1) {
      const rest  = loopBody.substring(sm.index + 6);
      const condM = rest.match(/^\s+([A-Za-z_]\w*)\s*(<|<=|==)\s*(\d+)\s*then/);
      if (condM) {
        headers.push({ kind: 'elseif', index: sm.index, matchEnd: sm.index + 6 + condM[0].length, threshold: parseInt(condM[3]), op: condM[2] });
      }
    } else if (kw === 'else' && depth === 1) {
      headers.push({ kind: 'else', index: sm.index, matchEnd: sm.index + 4 });
    } else if (kw === 'end') {
      if (depth === 1) {
        headers.push({ kind: 'end', index: sm.index, matchEnd: sm.index + 3 });
        depth--;
        break;  // トップレベルの if に対応する end を見つけた
      }
      depth--;
    } else if (kw === 'while' || kw === 'for' || kw === 'repeat' || kw === 'function') {
      depth++;
    } else if (kw === 'until') {
      depth--;
    }
  }

  // ── Phase 3: headers から body を切り出す ──────────────────────────
  const blocks = [];
  for (let i = 0; i < headers.length; i++) {
    const h = headers[i];
    if (h.kind === 'end') break;
    if (h.kind !== 'if' && h.kind !== 'elseif' && h.kind !== 'else') continue;

    const bodyStart = h.matchEnd;
    const bodyEnd   = (i + 1 < headers.length) ? headers[i + 1].index : loopBody.length;
    const body      = loopBody.substring(bodyStart, bodyEnd).trim();

    if (h.kind === 'else') {
      const lastThr = blocks.length > 0 ? blocks[blocks.length - 1].threshold + 1 : 255;
      blocks.push({ threshold: lastThr + 1, op: '>=', body, isElse: true });
    } else {
      blocks.push({ threshold: h.threshold, op: h.op, body });
    }
  }
  return blocks;
}

function _detectLoopVar(body) {
  const m = body.match(/\bif\s+([A-Za-z_]\w*)\s*[<>=!]/);
  return m ? m[1] : null;
}

function _reEsc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// ── trace / opcodeBlocks 構築 ───────────────────────────────────────────
function _buildTraceFromLoop(bestLoop, constPools, accessors, ctx, dispatchLoops) {
  const numbered = assignWeredevOpcodes(bestLoop.dispatchBlocks);
  const enriched = numbered.map(block => {
    const operands   = extractWeredevOperands(block.body || '', ctx);
    const detectedOp = _inferOpNameFromOperands(operands, block.body || '', ctx);
    return { ...block, opName: detectedOp, A: operands.A, B: operands.B, C: operands.C };
  });

  let emulTrace = [];
  try {
    const er = emulateWeredevVM({ constPools, accessors, dispatchLoops, ctx, numberedBlocks: enriched, options: { maxSteps: 100_000, maxTrace: 30_000 } });
    emulTrace = er.vmTrace || [];
  } catch {}

  const flatPool     = _buildFlatConstPool(constPools, accessors);
  const constLookup  = _buildConstLookup(constPools, accessors);

  const opcodeBlocks = enriched.map(block => {
    const instrLua      = vmDecompileInstruction(block.opName, block.estimatedOpcode, block.A, block.B, block.C, LUA51_OPCODES);
    const instrResolved = resolveInstrConstants(instrLua, flatPool);
    // rawBody は「このブロックだけ」の正確な本体
    return {
      threshold:       block.threshold,
      estimatedOpcode: block.estimatedOpcode,
      opName:          block.opName,
      A: block.A, B: block.B, C: block.C,
      instrLua:        instrResolved,
      ops:             analyzeWeredevOpcodeBlock(block, ctx),
      rawBody:         (block.body || '').substring(0, 500),
      constLookup,
      ctx,
    };
  });

  return { trace: emulTrace, opcodeBlocks, constPools, accessors, ctx, dispatchLoops, bestLoop, flatPool, constLookup };
}

// ════════════════════════════════════════════════════════════════════════
//  Step 4: VM interpreter (while J do) を Lua コードに変換
//
//  rawBody（各 opcode ブロックの正確なソース）から Lua 文を生成する。
//
//  優先順位:
//    1. rawBody を直接パース → 最も正確
//    2. instrLua (vmDecompileInstruction の出力) → フォールバック
//    3. ops[] (analyzeWeredevOpcodeBlock の出力) → 最終手段
// ════════════════════════════════════════════════════════════════════════
function convertVmToLua(opcodeBlocks, constPools, accessors, ctx) {
  if (!opcodeBlocks || opcodeBlocks.length === 0) return '';

  const constLookup = _buildConstLookup(constPools, accessors);
  const zFunc       = (ctx && ctx.zFunc)  || 'Z';
  const regVar      = (ctx && ctx.regVar) || 'V';

  const lines = [];
  lines.push('-- ════════════════════════════════════════════════════════');
  lines.push('-- Weredev VM → Lua (最終変換)');
  lines.push(`-- opcodeブロック数: ${opcodeBlocks.length}`);
  lines.push('-- ════════════════════════════════════════════════════════');
  lines.push('');

  let indentLevel = 0;
  const ind = () => '  '.repeat(Math.max(0, indentLevel));

  for (const block of opcodeBlocks) {
    const rawBody = block.rawBody || '';

    // ── 1. rawBody から Lua 文を直接生成 ─────────────────────────────
    const luaLines = _rawBodyToLua(rawBody, constLookup, zFunc, regVar);

    if (luaLines.length > 0) {
      if (block.opName === 'FORPREP') { indentLevel++; }
      if (block.opName === 'FORLOOP') { indentLevel = Math.max(0, indentLevel - 1); }
      for (const l of luaLines) lines.push(`${ind()}${l}`);
      continue;
    }

    // ── 2. instrLua フォールバック ────────────────────────────────────
    let luaLine = _resolveConstRefsInLine(block.instrLua || '', constLookup, zFunc);
    if (luaLine && !/^-- (OP_UNKNOWN|OP_\d|UNKNOWN)/.test(luaLine)) {
      if (block.opName === 'FORPREP') indentLevel++;
      if (block.opName === 'FORLOOP') indentLevel = Math.max(0, indentLevel - 1);
      lines.push(`${ind()}${luaLine}`);
      continue;
    }

    // ── 3. ops[] フォールバック ───────────────────────────────────────
    const opsLines = (block.ops || [])
      .filter(o => o.kind !== 'PC_INCR' && o.kind !== 'RAW')
      .map(o => _resolveConstRefsInLine(o.lua || '', constLookup, zFunc));
    if (opsLines.length > 0) {
      for (const l of opsLines) lines.push(`${ind()}${l}`);
      continue;
    }

    // ── 4. 最終フォールバック: コメント ──────────────────────────────
    lines.push(`${ind()}-- ${block.opName} A=${block.A} B=${block.B} C=${block.C}`);
  }

  return lines.join('\n');
}

/**
 * VM ブロックの rawBody (Lua ソーステキスト) を解析して
 * 意味のある Lua 文の配列を返す。
 *
 * 変換規則:
 *   V[N] = Z(M)      → local vN = <定数値>
 *   V[N] = V[M]      → local vN = vM
 *   V[N] = V[M] OP V[K] → local vN = vM OP vK
 *   V[N](V[M], ...)  → vN(vM, ...)
 *   V[N] = V[M](V[K], ...) → local vN = vM(vK, ...)
 *   return V[N]      → return vN
 *   V[N][K] = V[M]   → vN[K] = vM
 *   V[N] = V[M][K]   → local vN = vM[K]
 */
function _rawBodyToLua(rawBody, constLookup, zFunc, regVar) {
  if (!rawBody || rawBody.trim().length === 0) return [];

  const zf  = _reEsc(zFunc  || 'Z');
  const rv  = _reEsc(regVar || 'V');
  const out = [];

  // 1行ずつ処理（セミコロン区切りも考慮）
  const stmts = rawBody.split(/\n|;/).map(s => s.trim()).filter(s => s && !s.startsWith('--') && !s.startsWith('elseif') && !s.startsWith('else'));

  for (const stmt of stmts) {
    const lua = _convertStmt(stmt, constLookup, zf, rv, zFunc, regVar);
    if (lua) out.push(lua);
  }

  return out;
}

function _convertStmt(stmt, constLookup, zf, rv, zFunc, regVar) {
  let m;

  // return V[N]  /  return V[N], V[M], ...
  m = stmt.match(new RegExp(`^return\\s+(.+)$`));
  if (m) {
    const vals = m[1].split(',').map(v => _resolveValue(v.trim(), constLookup, zf, rv, zFunc, regVar));
    return `return ${vals.join(', ')}`;
  }

  // V[N] = V[M](args...)  (代入付き呼び出し)
  m = stmt.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*=\\s*(${rv}\\s*\\[\\d+\\]\\s*\\(.*\\))$`, 's'));
  if (m) {
    const lhs  = `v${m[1]}`;
    const rhs  = _resolveExpr(m[2], constLookup, zf, rv, zFunc, regVar);
    return `local ${lhs} = ${rhs}`;
  }

  // V[N](args...)  (関数呼び出し、代入なし)
  m = stmt.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*(\\([^)]*\\))$`));
  if (m) {
    const fn   = `v${m[1]}`;
    const args = _resolveArgList(m[2].slice(1, -1), constLookup, zf, rv, zFunc, regVar);
    return `${fn}(${args})`;
  }

  // V[N] = Z(M)  or  V[N] = <accessor>(M)
  m = stmt.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*=\\s*${zf}\\s*\\((\\d+)\\)$`));
  if (m) {
    const lhs   = `v${m[1]}`;
    const idx   = parseInt(m[2]);
    const val   = constLookup[idx] !== undefined ? _formatConst(constLookup[idx]) : `${zFunc}(${idx})`;
    return `local ${lhs} = ${val}`;
  }

  // V[N] = V[M] OP V[K]  (算術)
  m = stmt.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*=\\s*${rv}\\s*\\[(\\d+)\\]\\s*([+\\-*/%^])\\s*${rv}\\s*\\[(\\d+)\\]$`));
  if (m) return `local v${m[1]} = v${m[2]} ${m[3]} v${m[4]}`;

  // V[N] = V[M] .. V[K]  (文字列連結)
  m = stmt.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*=\\s*${rv}\\s*\\[(\\d+)\\]\\s*\\.\\.\\s*${rv}\\s*\\[(\\d+)\\]$`));
  if (m) return `local v${m[1]} = v${m[2]} .. v${m[3]}`;

  // V[N] = V[M][K]  (テーブル読み)
  m = stmt.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*=\\s*${rv}\\s*\\[(\\d+)\\]\\s*\\[(.+?)\\]$`));
  if (m) {
    const key = _resolveValue(m[3].trim(), constLookup, zf, rv, zFunc, regVar);
    return `local v${m[1]} = v${m[2]}[${key}]`;
  }

  // V[N][K] = V[M]  (テーブル書き)
  m = stmt.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*\\[(.+?)\\]\\s*=\\s*${rv}\\s*\\[(\\d+)\\]$`));
  if (m) {
    const key = _resolveValue(m[2].trim(), constLookup, zf, rv, zFunc, regVar);
    return `v${m[1]}[${key}] = v${m[3]}`;
  }

  // V[N] = {}
  m = stmt.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*=\\s*\\{\\s*\\}$`));
  if (m) return `local v${m[1]} = {}`;

  // V[N] = V[M]  (単純代入)
  m = stmt.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*=\\s*${rv}\\s*\\[(\\d+)\\]$`));
  if (m) return `local v${m[1]} = v${m[2]}`;

  // V[N] = -V[M]  /  V[N] = not V[M]  /  V[N] = #V[M]
  m = stmt.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*=\\s*(-|not\\s+|#)${rv}\\s*\\[(\\d+)\\]$`));
  if (m) return `local v${m[1]} = ${m[2].trim()} v${m[3]}`;

  // V[N] = <literal>  (数値/boolean/nil リテラル直接代入)
  m = stmt.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*=\\s*(true|false|nil|-?\\d+(?:\\.\\d+)?)$`));
  if (m) return `local v${m[1]} = ${m[2]}`;

  return null;  // マッチしない場合は呼び出し元でフォールバック
}

function _resolveValue(val, constLookup, zf, rv, zFunc, regVar) {
  const zm = val.match(new RegExp(`^${zf}\\s*\\((\\d+)\\)$`));
  if (zm) {
    const idx = parseInt(zm[1]);
    return constLookup[idx] !== undefined ? _formatConst(constLookup[idx]) : `${zFunc}(${idx})`;
  }
  const rm = val.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]$`));
  if (rm) return `v${rm[1]}`;
  if (/^-?\d+(\.\d+)?$/.test(val)) return val;
  if (val === 'true' || val === 'false' || val === 'nil') return val;
  return val;
}

function _resolveExpr(expr, constLookup, zf, rv, zFunc, regVar) {
  // V[N](args...) → vN(resolved_args)
  const callM = expr.match(new RegExp(`^${rv}\\s*\\[(\\d+)\\]\\s*\\((.*)\\)$`, 's'));
  if (callM) {
    const fn   = `v${callM[1]}`;
    const args = _resolveArgList(callM[2], constLookup, zf, rv, zFunc, regVar);
    return `${fn}(${args})`;
  }
  return _resolveValue(expr.trim(), constLookup, zf, rv, zFunc, regVar);
}

function _resolveArgList(argsStr, constLookup, zf, rv, zFunc, regVar) {
  if (!argsStr || !argsStr.trim()) return '';
  // 簡易分割（ネストした括弧は考慮しない）
  return argsStr.split(',').map(a => _resolveValue(a.trim(), constLookup, zf, rv, zFunc, regVar)).join(', ');
}

/** 定数参照 K[N] / Z(N) を値に解決（instrLua/ops の文字列用） */
function _resolveConstRefsInLine(line, constLookup, zFunc) {
  if (!line || !constLookup) return line;
  const zf = _reEsc(zFunc || 'Z');
  line = line.replace(/\bK\[(\d+)\]/g, (m, n) => {
    const v = constLookup[parseInt(n)];
    return v !== undefined ? _formatConst(v) : m;
  });
  line = line.replace(new RegExp(`\\b${zf}\\((\\d+)\\)`, 'g'), (m, n) => {
    const v = constLookup[parseInt(n)];
    return v !== undefined ? _formatConst(v) : m;
  });
  return line;
}

function _formatConst(v) {
  if (v === null || v === undefined) return 'nil';
  if (typeof v === 'boolean') return String(v);
  if (typeof v === 'number')  return String(v);
  if (typeof v === 'string') {
    const safe = v.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n');
    return `"${safe}"`;
  }
  return String(v);
}

function _buildConstLookup(constPools, accessors) {
  const lookup  = {};
  const accList = Object.values(accessors || {});
  if (accList.length > 0) {
    const acc  = accList[0];
    const pool = constPools[acc.poolName];
    if (pool && pool.elements) {
      pool.elements.forEach((e, i) => {
        if (!e) return;
        lookup[i]                   = e.value; // 0-indexed
        lookup[i + 1]               = e.value; // 1-indexed (Lua)
        const luaIdx = i + 1 + (acc.offset || 0);
        lookup[luaIdx]              = e.value; // アクセサオフセット補正
      });
    }
    return lookup;
  }
  let idx = 0;
  for (const pool of Object.values(constPools)) {
    if (!pool.elements) continue;
    for (const e of pool.elements) {
      if (e) { lookup[idx] = e.value; lookup[idx + 1] = e.value; }
      idx++;
    }
  }
  return lookup;
}

// ════════════════════════════════════════════════════════════════════════
//  Step 5: VM interpreter ブロックを削除し通常の Lua コードを出力
// ════════════════════════════════════════════════════════════════════════
function stripVmInterpreter(code, dispatchLoops, constPools, accessors, ctx) {
  if (!code) return code;
  let result = code;

  // ── 1: dispatch loop を後ろから削除 (座標保持のため先に実施) ──────────
  const sortedLoops = [...(dispatchLoops || [])].sort((a, b) => b.loopStart - a.loopStart);
  let removed = 0;
  for (const loop of sortedLoops) {
    if (loop.loopStart === undefined || loop.loopEnd === undefined) continue;
    result = result.substring(0, loop.loopStart)
           + `-- [VM dispatch loop removed: ${loop.blockCount} opcodes]\n`
           + result.substring(loop.loopEnd);
    removed++;
  }

  // ── 2: Z() 呼び出しを定数値に解決 ─────────────────────────────────
  result = resolveWeredevZCalls(result, accessors, constPools).code;

  // ── 3: フォールバック除去 (位置情報なしの場合) ───────────────────────
  if (removed === 0) {
    const loopVar  = ctx && ctx.loopVar ? ctx.loopVar : null;
    const candidates = new Set(loopVar ? [loopVar] : []);
    const wScan = /\bwhile\s+([A-Za-z_]\w*)\s+do\b/g;
    let ws;
    while ((ws = wScan.exec(result)) !== null) {
      if (ws[1] !== 'true' && ws[1] !== '1') candidates.add(ws[1]);
    }
    for (const lv of candidates) {
      const startIdx = result.indexOf('while ' + lv + ' do');
      if (startIdx === -1) continue;
      const snippet   = result.substring(startIdx, Math.min(result.length, startIdx + 50000));
      if (!/if\s+/.test(snippet)) continue;
      const endIdx    = _findWhileBodyEnd(result, startIdx + ('while ' + lv + ' do').length);
      if (endIdx === -1) continue;
      const endFull   = endIdx + 3;
      result = result.substring(0, startIdx) + '-- [VM dispatch loop removed]\n' + result.substring(endFull);
    }
  }

  // ── 4: 数値定数プール宣言を削除 ────────────────────────────────────
  result = result.replace(
    /local\s+[A-Za-z_]\w*\s*=\s*\{(?:\s*-?\d+(?:\.\d+)?\s*,){9,}[^}]*\}\s*\n?/g,
    '-- [const pool removed]\n'
  );

  // ── 5: アクセサ関数定義を削除 ──────────────────────────────────────
  result = result.replace(
    /local\s+[A-Za-z_]\w*\s*=\s*function\s*\([^)]+\)\s*return\s+[A-Za-z_]\w*\s*\[[^\]]+\]\s*end\s*\n?/g, ''
  );

  // ── 6: 文字列定数プール (文字列テーブル) を削除 ─────────────────────
  // local X = {"a","b","c",...} で要素が8個以上のもの
  result = result.replace(
    /local\s+[A-Za-z_]\w*\s*=\s*\{(?:\s*(?:"[^"]*"|'[^']*')\s*,\s*){7,}(?:"[^"]*"|'[^']*')\s*\}\s*\n?/g,
    '-- [string pool removed]\n'
  );

  // ── 7: 整形 ───────────────────────────────────────────────────────
  result = result.replace(/\n{4,}/g, '\n\n').replace(/[ \t]+$/gm, '');
  return result.trim();
}

// ════════════════════════════════════════════════════════════════════════
//  メイン: weredevFinalDecompile
// ════════════════════════════════════════════════════════════════════════
function weredevFinalDecompile(code, options) {
  const out = {
    success: false, finalCode: '', vmLua: '',
    steps: { escapeCount:0, base64Count:0, opcodeBlockCount:0, traceLen:0, resolvedZCalls:0 },
    error: null, method: 'weredev_final_decompile',
  };
  if (!code || code.length === 0) { out.error = 'コードが空です'; return out; }

  try {
    // Step 1
    const s1 = decodeNumericEscapes(code);
    out.steps.escapeCount = s1.count;
    let working = s1.code;

    // Step 2
    const s2 = decodeBase64Strings(working);
    out.steps.base64Count = s2.count;
    working = s2.code;

    // Step 3
    const s3 = buildExecutionTrace(working);
    out.steps.opcodeBlockCount = s3.opcodeBlocks.length;
    out.steps.traceLen         = s3.trace.length;

    // Step 4
    const vmLua = convertVmToLua(s3.opcodeBlocks, s3.constPools, s3.accessors, s3.ctx);
    out.vmLua = vmLua;

    // Step 5
    const stripped = stripVmInterpreter(working, s3.dispatchLoops, s3.constPools, s3.accessors, s3.ctx);
    out.steps.resolvedZCalls = (stripped.match(/\[VM dispatch loop removed|\[const pool removed|\[string pool removed/g) || []).length;

    const header = [
      '-- ════════════════════════════════════════════════════════',
      '-- Weredev VM 最終解読結果 (YAJU Deobfuscator v3)',
      `-- エスケープデコード: ${out.steps.escapeCount}件`,
      `-- Base64デコード:     ${out.steps.base64Count}件`,
      `-- opcodeブロック:     ${out.steps.opcodeBlockCount}件`,
      `-- execution trace:   ${out.steps.traceLen}命令`,
      '-- ════════════════════════════════════════════════════════',
      '',
    ].join('\n');

    const finalParts = [header];
    if (vmLua.length > 50) {
      finalParts.push(vmLua);
      finalParts.push('');
      finalParts.push('-- ── 残存コード (VM interpreter 除去後) ────────────────────');
    }
    if (stripped.length > 20) finalParts.push(stripped);

    out.finalCode = finalParts.join('\n').replace(/\n{4,}/g, '\n\n');
    out.success   = true;

  } catch (e) {
    out.error = 'weredevFinalDecompile エラー: ' + e.message + '\n' + (e.stack || '');
  }
  return out;
}

function weredevFinalDecompileHandler(code, options) {
  try { return weredevFinalDecompile(code, options); }
  catch (e) { return { success:false, finalCode:'', vmLua:'', steps:{}, error:'ハンドラエラー: '+e.message, method:'weredev_final_decompile' }; }
}

module.exports = {
  weredevFinalDecompile, weredevFinalDecompileHandler,
  decodeNumericEscapes, decodeBase64Strings,
  buildExecutionTrace, convertVmToLua, stripVmInterpreter,
  _unescapeLuaEscapes, _buildConstLookup, _sliceIfChain,
};
