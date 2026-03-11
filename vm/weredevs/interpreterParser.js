// vm/weredevs/interpreterParser.js
'use strict';

// ────────────────────────────────────────────────────────────────────────
//  項目14: while true do 解析専用の最大イテレーション制限
// ────────────────────────────────────────────────────────────────────────
const MAX_DISPATCH_ITERATIONS = 100000;

// ────────────────────────────────────────────────────────────────────────
//  detectWeredevContext — VM変数名をコードから動的検出
// ────────────────────────────────────────────────────────────────────────
function detectWeredevContext(code) {
  const ctx = {
    loopVar:   null,
    regVar:    'V',
    pcVar:     'pc',
    poolVar:   null,
    zFunc:     null,
    stackVar:  null,
    instrVar:  null,
  };

  // while VAR do → loopVar
  const whileM = code.match(/while\s+([A-Za-z_]\w*)\s+do\b/);
  if (whileM && whileM[1] !== 'true' && whileM[1] !== '1') ctx.loopVar = whileM[1];

  // local V[...] = ... → regVar
  const regM = code.match(/local\s+([A-Za-z_]\w*)\s*=\s*\{\s*\}/);
  if (regM) ctx.regVar = regM[1];

  // local pc = 1 → pcVar
  const pcM = code.match(/local\s+([A-Za-z_]\w*)\s*=\s*1\b/);
  if (pcM) ctx.pcVar = pcM[1];

  // local Z = function(i) return POOL[i ...] end → zFunc/poolVar
  const zM = code.match(/local\s+([A-Za-z_]\w*)\s*=\s*function\s*\(\s*\w+\s*\)\s*return\s+([A-Za-z_]\w*)\s*\[/);
  if (zM) { ctx.zFunc = zM[1]; ctx.poolVar = zM[2]; }

  // local stk = {} → stackVar
  const stkM = code.match(/local\s+([A-Za-z_]\w*)\s*=\s*\{\}[^\n]*stack/i);
  if (stkM) ctx.stackVar = stkM[1];

  // local inst / local l = B[pc] → instrVar
  const instrM = code.match(/local\s+(inst|[A-Za-z_]\w*)\s*=\s*\w+\s*\[\s*\w+\s*\]/);
  if (instrM) ctx.instrVar = instrM[1];

  return ctx;
}

// ────────────────────────────────────────────────────────────────────────
//  項目3: while state do VM ループ検出 → dispatcher 展開処理へ渡す
//  AST変換は行わず、dispatcherFlatten() に直接渡す
// ────────────────────────────────────────────────────────────────────────
function detectVmDispatchLoop(code) {
  const loops = [];

  // while VAR do（state-machine形式、VAR が真偽値変数）
  const stateLoopRe = /while\s+([A-Za-z_]\w*)\s+do\b/g;
  let m;
  while ((m = stateLoopRe.exec(code)) !== null) {
    const loopVar = m[1];
    if (loopVar === 'true' || loopVar === '1') continue;

    const loopStart = m.index;
    const loopBody  = _extractLoopBody(code, m.index + m[0].length);
    if (!loopBody) continue;

    // 項目3: while state do を検出したら AST に変換せず dispatcher 展開へ
    const dispatchInfo = _expandDispatcher(loopBody, loopVar);
    if (dispatchInfo.blocks.length > 0) {
      loops.push({
        type:       'state_machine',
        loopVar,
        loopStart,
        loopEnd:    loopStart + loopBody.length,
        body:       loopBody,
        dispatched: true,           // dispatcher 展開済みフラグ
        blocks:     dispatchInfo.blocks,
        blockCount: dispatchInfo.blocks.length,
        flatInstructions: dispatchInfo.flatInstructions,
      });
    }
  }

  // while true do / while 1 do（無限ループ型）
  const infLoopRe = /while\s+(?:true|1)\s+do\b/g;
  while ((m = infLoopRe.exec(code)) !== null) {
    const loopBody = _extractLoopBody(code, m.index + m[0].length);
    if (!loopBody) continue;

    // jVar を動的検出
    const jVarM = loopBody.match(/\bif\s+([A-Za-z_]\w*)\s*[<>=!]/);
    const jVar  = jVarM ? jVarM[1] : 'l';

    // 項目3同様: AST変換せず dispatcher 展開へ
    const dispatchInfo = _expandDispatcher(loopBody, jVar);
    if (dispatchInfo.blocks.length >= 3) {
      loops.push({
        type:       'infinite_loop',
        loopVar:    jVar,
        loopStart:  m.index,
        loopEnd:    m.index + loopBody.length,
        body:       loopBody,
        dispatched: true,
        blocks:     dispatchInfo.blocks,
        blockCount: dispatchInfo.blocks.length,
        flatInstructions: dispatchInfo.flatInstructions,
        isWhileTrue: true,
      });
    }
  }

  return loops;
}

// ────────────────────────────────────────────────────────────────────────
//  _expandDispatcher — if l < N then チェーンをフラットな命令列へ展開
//  項目3: AST変換なし、項目9: switch-case構造への変換
// ────────────────────────────────────────────────────────────────────────
function _expandDispatcher(loopBody, jVar) {
  const blocks = [];
  const flatInstructions = [];

  // 項目9: 巨大な if l < 数値 then チェーンを検出
  const ifChainDepth = _countIfChainDepth(loopBody, jVar);
  const isSwitchCandidate = ifChainDepth >= 4;

  _flattenDispatchTree(loopBody, jVar, blocks, 0, MAX_DISPATCH_ITERATIONS);

  // ソートしてフラット命令列を生成
  blocks.sort((a, b) => a.opcodeEstimate - b.opcodeEstimate);

  for (const block of blocks) {
    flatInstructions.push({
      opcode:      block.opcodeEstimate,
      body:        block.body,
      threshold:   block.threshold,
      switchLabel: isSwitchCandidate ? `case_${block.opcodeEstimate}` : null,
    });
  }

  return { blocks, flatInstructions, isSwitchCandidate };
}

function _countIfChainDepth(src, jVar) {
  const re = new RegExp(`\\bif\\s+${_escRe(jVar)}\\s*<\\s*\\d+\\s*then`, 'g');
  let count = 0, m;
  while ((m = re.exec(src)) !== null) count++;
  return count;
}

function _flattenDispatchTree(src, jVar, out, depth, maxDepth) {
  if (depth > maxDepth) return;  // 項目14: 無限ループ防止

  const ifRe = new RegExp(`\\bif\\s+${_escRe(jVar)}\\s*(<|<=|==)\\s*(\\d+)\\s*then`);
  const m = ifRe.exec(src);
  if (!m) {
    // 末端ノード: opcode ブロックとして収集
    const trimmed = src.trim();
    if (trimmed.length > 3 && !/^end\s*$/.test(trimmed)) {
      out.push({
        opcodeEstimate: out.length,
        threshold:      out.length,
        body:           trimmed,
        depth,
      });
    }
    return;
  }

  const threshold = parseInt(m[2]);
  const thenStart = m.index + m[0].length;
  const { thenBody, elseBody } = _splitThenElse(src, thenStart);

  // then 側を再帰展開
  const hasNestedIf = new RegExp(`\\bif\\s+${_escRe(jVar)}\\s*[<>=!]`).test(thenBody);
  if (hasNestedIf) {
    _flattenDispatchTree(thenBody, jVar, out, depth + 1, maxDepth);
  } else if (thenBody.trim().length > 3) {
    out.push({
      opcodeEstimate: threshold - 1,
      threshold,
      body:           thenBody.trim(),
      depth,
    });
  }

  // else 側を再帰展開
  if (elseBody && elseBody.trim().length > 3) {
    const hasNestedIfElse = new RegExp(`\\bif\\s+${_escRe(jVar)}\\s*[<>=!]`).test(elseBody);
    if (hasNestedIfElse) {
      _flattenDispatchTree(elseBody, jVar, out, depth + 1, maxDepth);
    } else {
      out.push({
        opcodeEstimate: threshold,
        threshold:      threshold + 1,
        body:           elseBody.trim(),
        depth,
      });
    }
  }
}

// ────────────────────────────────────────────────────────────────────────
//  項目4: dynamic opcode resolver
//  opcodeMap を固定参照せず vmhook ログ（実行トレース）から再構築する
// ────────────────────────────────────────────────────────────────────────
function dynamicOpcodeResolver(vmTraceEntries, bTableInstructions, staticFallback) {
  // 項目15: VMhookログが存在する場合は opcode 実行順を優先
  if (vmTraceEntries && vmTraceEntries.length > 0) {
    return _buildFromTrace(vmTraceEntries, bTableInstructions);
  }
  // 項目15: ログが存在しない場合のみ静的解析へフォールバック
  if (staticFallback) {
    return { opcodeMap: staticFallback, source: 'static_fallback', confidence: 30 };
  }
  return { opcodeMap: {}, source: 'empty', confidence: 0 };
}

function _buildFromTrace(entries, bInstructions) {
  // opcode 実行順カウント（l フィールド優先）
  const execOrder  = [];   // 実行順に並んだ opcode 値
  const freq       = {};
  const seqPairs   = {};   // 連続 opcode ペア (A→B) の頻度

  let prev = null;
  for (const e of entries) {
    const op = e.l !== undefined ? e.l : e.op;
    if (op === null || op === undefined) continue;
    const k = String(op);
    freq[k]  = (freq[k] || 0) + 1;
    execOrder.push(op);
    if (prev !== null) {
      const pair = `${prev}->${k}`;
      seqPairs[pair] = (seqPairs[pair] || 0) + 1;
    }
    prev = k;
  }

  // bTable との照合: bTable の op フィールドで直接名前を得られる場合がある
  const knownMap = {};
  if (bInstructions) {
    for (const inst of bInstructions.slice(0, 500)) {
      if (inst.opName && inst.op !== undefined) {
        knownMap[String(inst.op)] = inst.opName;
      }
    }
  }

  // 実行頻度パターンからヒューリスティック推論
  const sortedFreq = Object.entries(freq)
    .sort((a, b) => b[1] - a[1]);

  // Weredevs は opcode をシャッフルするため実行頻度で推定
  // MOVE/LOADK/CALL/RETURN は頻度が高い傾向
  const heuristicNames = ['MOVE', 'LOADK', 'CALL', 'RETURN', 'GETTABLE', 'SETTABLE',
                          'ADD', 'SUB', 'JMP', 'EQ', 'LT', 'LE', 'GETGLOBAL'];
  const assigned = new Set(Object.values(knownMap));
  const opcodeMap = { ...knownMap };

  for (let i = 0; i < Math.min(sortedFreq.length, heuristicNames.length); i++) {
    const [opKey] = sortedFreq[i];
    if (opKey in opcodeMap) continue;
    let name = heuristicNames[i];
    // 既に別のopcodeに割り当て済みならスキップ
    if (assigned.has(name)) continue;
    opcodeMap[opKey] = name + '_heuristic';
    assigned.add(name);
  }

  const confidence = Object.keys(knownMap).length > 0
    ? Math.min(95, 50 + Object.keys(knownMap).length * 3)
    : Math.min(40, sortedFreq.length * 2);

  return {
    opcodeMap,
    execOrder: execOrder.slice(0, 1000),
    frequency: sortedFreq.slice(0, 30),
    seqPairs:  Object.entries(seqPairs).sort((a,b) => b[1]-a[1]).slice(0, 20),
    source:    'vmhook_trace',
    confidence,
  };
}

// ────────────────────────────────────────────────────────────────────────
//  analyzeWeredevOpcodeBlock — 単一 opcode ブロックの意味解析
// ────────────────────────────────────────────────────────────────────────
function analyzeWeredevOpcodeBlock(block, ctx) {
  const body = block.body || block.rawBody || '';
  const ops  = [];
  const regV = (ctx && ctx.regVar)  || 'V';
  const pcV  = (ctx && ctx.pcVar)   || 'pc';
  const zFn  = (ctx && ctx.zFunc)   || 'Z';

  // PC インクリメント検出
  if (new RegExp(`\\b${_escRe(pcV)}\\s*=\\s*${_escRe(pcV)}\\s*\\+`).test(body)) {
    const m = body.match(new RegExp(`${_escRe(pcV)}\\s*=\\s*${_escRe(pcV)}\\s*\\+\\s*(\\d+)`));
    ops.push({ kind: 'PC_INCR', amount: m ? parseInt(m[1]) : 1, lua: `${pcV} = ${pcV} + ${m ? m[1] : '1'}` });
  }

  // レジスタ代入 V[A] = ...
  const regAssign = new RegExp(`${_escRe(regV)}\\s*\\[(\\d+)\\]\\s*=\\s*([^\\n;]+)`, 'g');
  let rm;
  while ((rm = regAssign.exec(body)) !== null) {
    const reg = parseInt(rm[1]);
    const rhs = rm[2].trim();
    let kind = 'ASSIGN';
    if (new RegExp(`${_escRe(zFn)}\\s*\\(`).test(rhs))     kind = 'LOADK';
    else if (/^\-?[\d.]+$/.test(rhs))                       kind = 'LOADNUM';
    else if (/^["']|^\[\[/.test(rhs))                       kind = 'LOADSTR';
    else if (new RegExp(`${_escRe(regV)}\\s*\\[`).test(rhs)) kind = 'MOVE';
    ops.push({ kind, reg, rhs, lua: `${regV}[${reg}] = ${rhs}` });
  }

  // 関数呼び出し V[A](...)
  const callPat = new RegExp(`${_escRe(regV)}\\s*\\[(\\d+)\\]\\s*\\(([^)]*)\\)`, 'g');
  let cm;
  while ((cm = callPat.exec(body)) !== null) {
    const fnReg = parseInt(cm[1]);
    const args  = cm[2].trim();
    ops.push({ kind: 'CALL', fnReg, args, lua: `${regV}[${fnReg}](${args})` });
  }

  // RETURN
  if (/\breturn\b/.test(body) && !/function/.test(body)) {
    const retM = body.match(/return\s*([^\n]*)/);
    ops.push({ kind: 'RETURN', lua: retM ? retM[0].trim() : 'return' });
  }

  // テーブルアクセス V[A][key]
  const tblGet = new RegExp(`${_escRe(regV)}\\s*\\[(\\d+)\\]\\s*=\\s*${_escRe(regV)}\\s*\\[(\\d+)\\]\\s*\\[([^\\]]+)\\]`, 'g');
  let tg;
  while ((tg = tblGet.exec(body)) !== null) {
    ops.push({ kind: 'GETTABLE', A: parseInt(tg[1]), B: parseInt(tg[2]), C: tg[3].trim(), lua: `${regV}[${tg[1]}] = ${regV}[${tg[2]}][${tg[3]}]` });
  }

  // RAW フォールバック
  if (ops.length === 0) {
    ops.push({ kind: 'RAW', lua: body.trim().substring(0, 200) });
  }

  return ops;
}

// ────────────────────────────────────────────────────────────────────────
//  extractWeredevOperands — opcode ブロック本体からA/B/Cを抽出
// ────────────────────────────────────────────────────────────────────────
function extractWeredevOperands(body, ctx) {
  const regV = (ctx && ctx.regVar) || 'V';
  const result = { A: null, B: null, C: null, _op: null };
  if (!body) return result;

  // A: 代入先レジスタ V[N] =
  const aM = body.match(new RegExp(`${_escRe(regV)}\\s*\\[(\\d+)\\]\\s*=`));
  if (aM) result.A = parseInt(aM[1]);

  // B, C: 右辺のレジスタ参照
  const rhsM = body.match(new RegExp(`=\\s*(?:.*?)${_escRe(regV)}\\s*\\[(\\d+)\\]`));
  if (rhsM) result.B = parseInt(rhsM[1]);
  const allRegs = [...body.matchAll(new RegExp(`${_escRe(regV)}\\s*\\[(\\d+)\\]`, 'g'))];
  if (allRegs.length >= 3) result.C = parseInt(allRegs[2][1]);
  else if (allRegs.length >= 2 && result.A !== null && parseInt(allRegs[1][1]) !== result.A)
    result.B = parseInt(allRegs[1][1]);

  // 算術演算子
  const arithM = body.match(/([+\-*\/%^])/);
  if (arithM) result._op = arithM[1];

  return result;
}

// ────────────────────────────────────────────────────────────────────────
//  _buildFlatConstPool — 複数の constPool を統合フラット配列にする
// ────────────────────────────────────────────────────────────────────────
function _buildFlatConstPool(constPools, accessors) {
  const flat = {};
  for (const [accName, acc] of Object.entries(accessors || {})) {
    const pool = constPools && constPools[acc.poolName];
    if (!pool) continue;
    flat[accName] = {
      funcName: acc.funcName,
      poolName: acc.poolName,
      offset:   acc.offset,
      elements: pool.elements,
    };
  }
  // アクセサがない場合は全プールをそのまま追加
  if (Object.keys(flat).length === 0 && constPools) {
    for (const [name, pool] of Object.entries(constPools)) {
      if (pool.isLikelyConstPool) {
        flat[name] = { funcName: name, poolName: name, offset: 0, elements: pool.elements };
      }
    }
  }
  return flat;
}

// ────────────────────────────────────────────────────────────────────────
//  resolveWeredevZCalls — Z(N) → 定数値に置換
// ────────────────────────────────────────────────────────────────────────
function resolveWeredevZCalls(code, accessors, constPools) {
  let result = code;
  let resolved = 0;

  for (const [funcName, acc] of Object.entries(accessors || {})) {
    const pool = constPools && constPools[acc.poolName];
    if (!pool) continue;

    const fnEsc = _escRe(funcName);
    const re = new RegExp(`\\b${fnEsc}\\s*\\(\\s*(-?\\d+)\\s*\\)`, 'g');
    result = result.replace(re, (match, idxStr) => {
      const idx     = parseInt(idxStr);
      const realIdx = idx + acc.offset;   // offset 調整
      const elem    = pool.elements[realIdx - 1] || pool.elements[realIdx];
      if (!elem) return match;
      resolved++;
      if (elem.type === 'string') {
        const safe = elem.value.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n');
        return `"${safe}"`;
      }
      if (elem.type === 'number') return String(elem.value);
      if (elem.type === 'bool')   return String(elem.value);
      if (elem.type === 'nil')    return 'nil';
      return match;
    });
  }

  return { code: result, resolved };
}

// ────────────────────────────────────────────────────────────────────────
//  ヘルパー
// ────────────────────────────────────────────────────────────────────────
function _escRe(s) {
  return (s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function _extractLoopBody(code, startAfterDo) {
  let depth = 1, i = startAfterDo;
  const limit = Math.min(code.length, startAfterDo + 5000000);
  while (i < limit) {
    const sub     = code.slice(i);
    const nextKw  = sub.search(/\b(do|then|repeat|function)\b/);
    const nextEnd = sub.search(/\bend\b/);
    if (nextEnd === -1) break;
    if (nextKw !== -1 && nextKw < nextEnd) {
      depth++; i += nextKw + 2;
    } else {
      depth--;
      if (depth === 0) return code.substring(startAfterDo, i + nextEnd + 3);
      i += nextEnd + 3;
    }
  }
  return null;
}

function _splitThenElse(src, thenStart) {
  let depth = 1, elsePos = -1;
  const keywords = /\b(if|while|for|repeat|do|function)\b|\b(end|until)\b|\belse(?:if)?\b/g;
  keywords.lastIndex = thenStart;
  let km;
  while ((km = keywords.exec(src)) !== null) {
    const kw = km[0];
    if (/^(if|while|for|function|do|repeat)$/.test(kw)) depth++;
    else if (kw === 'end' || kw === 'until') {
      depth--;
      if (depth === 0) {
        const endPos = km.index;
        if (elsePos !== -1)
          return { thenBody: src.substring(thenStart, elsePos), elseBody: src.substring(elsePos + 4, endPos) };
        return { thenBody: src.substring(thenStart, endPos), elseBody: '' };
      }
    } else if ((kw === 'else' || kw === 'elseif') && depth === 1) {
      elsePos = km.index;
    }
  }
  return { thenBody: src.substring(thenStart), elseBody: '' };
}

module.exports = {
  detectWeredevContext,
  detectVmDispatchLoop,
  dynamicOpcodeResolver,
  analyzeWeredevOpcodeBlock,
  extractWeredevOperands,
  _buildFlatConstPool,
  resolveWeredevZCalls,
  MAX_DISPATCH_ITERATIONS,
};
