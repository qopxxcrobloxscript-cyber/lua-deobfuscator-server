// vm/weredevs/extractor.js
'use strict';

function extractVmTableNames(code) {
  const names = [];
  const seen  = new Set();
  const re    = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const name = m[1];
    if (!seen.has(name)) {
      seen.add(name);
      names.push(name);
    }
  }
  return names;
}

// ── 項目 2: new RegExp で VMテーブルを抽出 ──────────────────────────────
// WeredevのBテーブル(bytecode)・定数テーブルなど数値が50要素以上のものを抽出
function extractVmTable(code, vmTableName) {
  if (!vmTableName || !code) return null;
  // ネストした {} を正しく扱うため、{ の位置から対応する } を探す
  const startRe = new RegExp('local\\s+' + vmTableName.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + '\\s*=\\s*\\{');
  const startM  = startRe.exec(code);
  if (!startM) return null;

  // 対応する閉じ括弧を探す（ネスト深度カウント）
  let depth = 0, pos = startM.index + startM[0].length - 1;
  const end = Math.min(code.length, pos + 200000);
  let tableEnd = -1;
  for (let i = pos; i < end; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') {
      depth--;
      if (depth === 0) { tableEnd = i; break; }
    }
  }
  if (tableEnd === -1) return null;

  const body = code.substring(pos + 1, tableEnd);
  // 数値要素を抽出
  const nums  = body.split(',').map(s => {
    const t = s.trim().replace(/\s*--[^\n]*/g, '');
    return isNaN(Number(t)) ? null : Number(t);
  }).filter(n => n !== null);

  // テーブルの内容を構造化（要素がテーブル形式 {a,b,c,d} の場合も対応）
  const subTables = [];
  const subRe = /\{([^{}]+)\}/g;
  let sm;
  while ((sm = subRe.exec(body)) !== null) {
    const inner = sm[1].split(',').map(s => {
      const t = s.trim();
      return isNaN(Number(t)) ? t : Number(t);
    });
    subTables.push(inner);
  }

  return {
    name: vmTableName,
    raw:  body.substring(0, 500),
    nums,
    subTables: subTables.slice(0, 200),
    count: nums.length,
    isLikelyBytecode: nums.length >= 10 && Math.max(...nums.filter(n=>typeof n==='number')) < 65536,
  };
}

// ── 項目 3: decodeEscapedString — \DDD → ASCII 変換 ─────────────────────
function extractWeredevConstPool(code) {
  const pools = {};
  const tableRe = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{/g;
  let m;
  while ((m = tableRe.exec(code)) !== null) {
    const varName = m[1];
    const startPos = m.index + m[0].length - 1;
    let depth = 0, pos = startPos, end = -1;
    const limit = Math.min(code.length, startPos + 2000000);
    for (let i = startPos; i < limit; i++) {
      if (code[i] === '{') depth++;
      else if (code[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
    }
    if (end === -1) continue;
    const body = code.substring(startPos + 1, end);
    const elements = parseConstPoolBody(body);
    if (elements.length < 1) continue;
    pools[varName] = {
      name: varName, elements,
      count: elements.length,
      startPos: m.index, endPos: end + 1,
      isLikelyConstPool: detectIfConstPool(elements),
    };
  }
  return pools;
}
function parseConstPoolBody(body) {
  const elements = [];
  let i = 0, cur = '', depth = 0, inStr = false, strCh = '';
  while (i < body.length) {
    const c = body[i];
    if (!inStr) {
      if (c === '"' || c === "'") { inStr = true; strCh = c; cur += c; }
      else if (c === '[' && body[i+1] === '[') {
        let e = body.indexOf(']]', i + 2); if (e === -1) e = body.length - 2;
        cur += body.substring(i, e + 2); i = e + 2; continue;
      }
      else if (c === '{') { depth++; cur += c; }
      else if (c === '}') { depth--; cur += c; }
      else if (c === ',' && depth === 0) {
        const elem = resolveConstPoolElement(cur.trim());
        if (elem !== undefined) elements.push(elem);
        cur = '';
      } else cur += c;
    } else {
      if (c === '\\') { cur += c + (body[i+1] || ''); i += 2; continue; }
      if (c === strCh) inStr = false;
      cur += c;
    }
    i++;
  }
  if (cur.trim()) { const elem = resolveConstPoolElement(cur.trim()); if (elem !== undefined) elements.push(elem); }
  return elements;
}
function resolveConstPoolElement(tok) {
  if (!tok) return undefined;
  const keyValM = tok.match(/^\s*\[\s*-?\d+\s*\]\s*=\s*(.+)$/s);
  if (keyValM) tok = keyValM[1].trim();
  if ((tok.startsWith('"') && tok.endsWith('"')) || (tok.startsWith("'") && tok.endsWith("'"))) {
    return { type: 'string', raw: tok, value: tok.slice(1,-1)
      .replace(/\\n/g,'\n').replace(/\\t/g,'\t').replace(/\\r/g,'\r')
      .replace(/\\\\/g,'\\').replace(/\\"/g,'"').replace(/\\'/g,"'")
      .replace(/\\(\d{1,3})/g,(_,d)=>String.fromCharCode(parseInt(d)))
      .replace(/\\x([0-9a-fA-F]{2})/g,(_,h)=>String.fromCharCode(parseInt(h,16))) };
  }
  if (tok.startsWith('[[') && tok.endsWith(']]')) return { type:'string', raw:tok, value:tok.slice(2,-2) };
  if (tok === 'nil')   return { type:'nil',  raw:tok, value:null };
  if (tok === 'true')  return { type:'bool', raw:tok, value:true };
  if (tok === 'false') return { type:'bool', raw:tok, value:false };
  const n = Number(tok.replace(/_/g,''));
  if (!isNaN(n) && tok !== '') return { type:'number', raw:tok, value:n };
  try {
    if (/^[\d\s+\-*/().\^%]+$/.test(tok)) {
      const v = Function('"use strict";return('+tok+')')();
      if (typeof v==='number' && isFinite(v)) return { type:'number', raw:tok, value:v };
    }
  } catch {}
  return { type:'expr', raw:tok, value:tok };
}
function detectIfConstPool(elements) {
  if (elements.length === 0) return false;
  if (elements.length < 4) return true; // アクセサで参照される場合は小さくても有効
  const strCount = elements.filter(e => e && e.type === 'string').length;
  const numCount = elements.filter(e => e && e.type === 'number').length;
  return strCount >= 2 || numCount >= 10 || (strCount >= 1 && numCount >= 2) || elements.length >= 4;
}

// ────────────────────────────────────────────────────────────────────────
//  Step 2: Z(i) アクセサ解析
//  local Z = function(i) return R[i - OFFSET] end
// ────────────────────────────────────────────────────────────────────────
function extractWeredevZAccessor(code, constPools) {
  const accessors = {};
  const patterns = [
    /local\s+([A-Za-z_]\w*)\s*=\s*function\s*\(\s*([A-Za-z_]\w*)\s*\)\s*return\s+([A-Za-z_]\w*)\s*\[\s*\2\s*([\+\-])\s*(\d+)\s*\]\s*end/g,
    /local\s+([A-Za-z_]\w*)\s*=\s*function\s*\(\s*([A-Za-z_]\w*)\s*\)\s*return\s+([A-Za-z_]\w*)\s*\[\s*\2\s*\]\s*end/g,
    /\b([A-Za-z_]\w*)\s*=\s*function\s*\(\s*([A-Za-z_]\w*)\s*\)\s*return\s+([A-Za-z_]\w*)\s*\[\s*\2\s*([\+\-])\s*(\d+)\s*\]\s*end/g,
  ];
  for (const re of patterns) {
    let m; re.lastIndex = 0;
    while ((m = re.exec(code)) !== null) {
      const funcName = m[1], poolName = m[3];
      const sign = m[4] || '+', rawOffset = m[5] ? parseInt(m[5]) : 0;
      const offset = sign === '-' ? rawOffset : -rawOffset;
      if (constPools && (constPools[poolName] !== undefined)) {
        accessors[funcName] = { funcName, poolName, offset, sign, raw: m[0] };
      } else if (!constPools) {
        accessors[funcName] = { funcName, poolName, offset, sign, raw: m[0] };
      }
    }
  }
  return accessors;
}

// ────────────────────────────────────────────────────────────────────────
//  Step 3: while J do ディスパッチループ抽出
// ────────────────────────────────────────────────────────────────────────
function _wdEscapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ── extractIfJBlocks ────────────────────────────────────────────────────
// while J do の本体から  if J < N then ... end  ブロックを再帰的にフラット展開する。
// Weredevは二分探索木形式でopcodeをディスパッチするため、ネストした if J<midpoint then
// の葉ノードが実際のopcodeに相当する。
// アルゴリズム:
//   1. 現在のブロック内で最初の "if jVar <OP> N then" を見つける
//   2. 対応する end まで本体を抽出 (depth計算)
//   3. then/else の各ブランチを再帰処理してフラット化
//   4. 葉ノード (内部に if jVar が存在しない) をブロックとして登録
function extractIfJBlocks(loopBody, jVar) {
  if (!jVar) {
    const m = loopBody.match(/\bif\s+([A-Za-z_]\w*)\s*[<>=!]/);
    jVar = m ? m[1] : 'J';
  }
  const blocks = [];
  _flattenIfJTree(loopBody, jVar, blocks);
  // 閾値昇順でソート
  blocks.sort((a, b) => a.threshold - b.threshold);
  return blocks;
}

// 再帰的にif-then-elseツリーを展開してleafブロックを収集
function _flattenIfJTree(src, jVar, out) {
  const ifRe = new RegExp(`\\bif\\s+${_wdEscapeRegex(jVar)}\\s*(<|<=|==|>=|>)\\s*(\\d+)\\s*then`);
  const m = ifRe.exec(src);
  if (!m) {
    // if J<N が存在しない → 単独文があれば葉ノードとして収集
    _collectLeafStatements(src, jVar, out);
    return;
  }

  const op        = m[1];
  const threshold = parseInt(m[2]);
  const thenStart = m.index + m[0].length;

  // if J<N より前に単独文があれば葉ノードとして収集
  const beforeIf = src.substring(0, m.index).trim();
  if (beforeIf.length > 5) {
    _collectLeafStatements(beforeIf, jVar, out, threshold - 0.5); // 小数で位置保持
  }

  // then本体と else/elseif/end の境界をdepth計算で特定
  const { thenBody, elseBody } = _splitIfThenElse(src, thenStart);

  // thenブランチ: 内部に if jVar があればさらに再帰
  const ifReThen = new RegExp(`\\bif\\s+${_wdEscapeRegex(jVar)}\\s*[<>=!]`);
  if (ifReThen.test(thenBody)) {
    _flattenIfJTree(thenBody, jVar, out);
  } else if (thenBody.trim().length > 0) {
    // 葉ノード → opcodeブロックとして登録
    out.push({ op, threshold, body: thenBody.trim(), pos: m.index, headerLen: m[0].length });
  }

  // elseブランチ (存在すれば)
  if (elseBody && elseBody.trim().length > 0) {
    if (ifReThen.test(elseBody)) {
      _flattenIfJTree(elseBody, jVar, out);
    } else {
      out.push({ op: '>=', threshold: threshold + 1, body: elseBody.trim(), pos: m.index + m[0].length });
    }
  }

  // m.index より後の同レベルブロックも処理 (兄弟ノードの探索)
  const afterIf = _findIfBlockEnd(src, m.index);
  if (afterIf < src.length - 5) {
    _flattenIfJTree(src.substring(afterIf), jVar, out);
  }
}

// if J<N を含まない単純文を葉ノードとして収集
function _collectLeafStatements(src, jVar, out, hintThreshold) {
  const trimmed = src.trim();
  if (!trimmed || trimmed.length < 3) return;
  // コメントのみなら無視
  if (/^--/.test(trimmed)) return;
  // ifや他の制御文が含まれていれば無視
  if (/\b(if|while|for|repeat)\b/.test(trimmed)) return;
  // end のみも無視
  if (/^end\s*$/.test(trimmed)) return;
  // 有効な文として登録
  out.push({
    op: '<',
    threshold: Math.round(hintThreshold || 0) + 1,
    body: trimmed,
    pos: -1,
    headerLen: 0,
    isImplicitLeaf: true,
  });
}

// if...then...else...end の then本体 / else本体を分離
function _splitIfThenElse(src, thenStart) {
  let depth = 1, i = thenStart;
  let elsePos = -1;
  const keywords = /\b(if|while|for|repeat|do|function)\b|\b(end|until)\b|\belse(?:if)?\b/g;
  keywords.lastIndex = thenStart;
  let km;
  while ((km = keywords.exec(src)) !== null) {
    const kw = km[0];
    if (/^(if|while|for|function|do|repeat)$/.test(kw)) {
      depth++;
    } else if (kw === 'end' || kw === 'until') {
      depth--;
      if (depth === 0) {
        const endPos = km.index;
        if (elsePos !== -1) {
          return { thenBody: src.substring(thenStart, elsePos), elseBody: src.substring(elsePos + 4, endPos) };
        }
        return { thenBody: src.substring(thenStart, endPos), elseBody: '' };
      }
    } else if ((kw === 'else' || kw === 'elseif') && depth === 1) {
      elsePos = km.index;
    }
  }
  // endが見つからない場合はsrc末尾まで
  return { thenBody: src.substring(thenStart), elseBody: '' };
}

// if...end ブロック全体の終端位置を返す
function _findIfBlockEnd(src, ifStart) {
  let depth = 0;
  const keywords = /\b(if|while|for|repeat|do|function)\b|\bend\b/g;
  keywords.lastIndex = ifStart;
  let m;
  while ((m = keywords.exec(src)) !== null) {
    if (/^(if|while|for|function|do|repeat)$/.test(m[0])) depth++;
    else if (m[0] === 'end') {
      depth--;
      if (depth === 0) return m.index + 3;
    }
  }
  return src.length;
}
function extractWeredevDispatchLoop(code) {
  const loops = [];
  // while VAR do
  const whileRe = /while\s+([A-Za-z_]\w*)\s+do\b/g;
  let m;
  while ((m = whileRe.exec(code)) !== null) {
    const loopVar = m[1];
    if (loopVar === 'true' || loopVar === '1') continue;
    const doIdx = code.indexOf('do', m.index + m[0].length - 3);
    if (doIdx === -1) continue;
    let depth = 1, end = -1;
    let scan = doIdx + 2;
    const limit = Math.min(code.length, doIdx + 5000000);
    while (scan < limit) {
      const sub = code.slice(scan);
      const doM = sub.match(/^[\s\S]*?\b(do|then|repeat)\b/);
      const endM = sub.match(/^[\s\S]*?\bend\b/);
      const nextDo  = sub.search(/\b(do|then|repeat)\b/);
      const nextEnd = sub.search(/\bend\b/);
      if (nextEnd === -1) break;
      if (nextDo !== -1 && nextDo < nextEnd) { depth++; scan += nextDo + 2; }
      else { depth--; if (depth === 0) { end = scan + nextEnd + 3; break; } scan += nextEnd + 3; }
    }
    if (end === -1) continue;
    const loopBody = code.substring(m.index, end);
    const dispatchBlocks = extractIfJBlocks(loopBody, loopVar);
    if (dispatchBlocks.length < 1) continue;
    loops.push({ loopVar, loopStart: m.index, loopEnd: end, body: loopBody, dispatchBlocks, blockCount: dispatchBlocks.length });
  }
  // while true do もサーチ
  const whileTrueRe = /while\s+true\s+do\b/g;
  while ((m = whileTrueRe.exec(code)) !== null) {
    const snippet = code.substring(m.index, Math.min(code.length, m.index + 500000));
    const blocks = extractIfJBlocks(snippet, null);
    if (blocks.length >= 3) {
      const jVarM = snippet.match(/if\s+([A-Za-z_]\w*)\s*[<>=!]/);
      const lv = jVarM ? jVarM[1] : 'J';
      loops.push({ loopVar: lv, loopStart: m.index, loopEnd: m.index + snippet.length,
        body: snippet, dispatchBlocks: blocks, blockCount: blocks.length, isWhileTrue: true });
    }
  }
  return loops;
}

// ────────────────────────────────────────────────────────────────────────
//  Step 4: 閾値→opcode番号マッピング
// ────────────────────────────────────────────────────────────────────────
function dumpBytecodeTables(code) {
  const candidates = [];
  const tblPat = /local\s+(\w+)\s*=\s*\{([\s\d,]+)\}/g;
  let m;
  while ((m = tblPat.exec(code)) !== null) {
    const nums = m[2].split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
    if (nums.length >= 50) candidates.push({ name: m[1], count: nums.length });
  }
  if (candidates.length === 0) return { code, injected: false, candidates: [] };
  let inject = '\n-- ══ YAJU Bytecode Dump ══\n';
  for (const c of candidates) {
    inject += `if type(${c.name})=="table" then\n  for __i,__v in ipairs(${c.name}) do\n    print("__BYTECODE__\\t${c.name}\\t"..tostring(__i).."\\t"..tostring(__v))\n  end\nend\n`;
  }
  return { code: code + inject, injected: true, candidates };
}

// ────────────────────────────────────────────────────────────────────────
//  #55  beautifyLua — 最終コード整形
// ────────────────────────────────────────────────────────────────────────
function vmBytecodeExtractor(code) {
  const tables = [];
  const tblPattern = /local\s+(\w+)\s*=\s*\{((?:\s*\d+\s*,){10,}[^}]*)\}/g;
  let m;
  while ((m = tblPattern.exec(code)) !== null) {
    const name = m[1];
    const nums = m[2].split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
    if (nums.length >= 10) {
      const max = Math.max(...nums);
      tables.push({ name, count: nums.length, sample: nums.slice(0,16), isLikelyBytecode: max < 65536 });
    }
  }
  if (tables.length === 0) return { success: false, error: 'バイトコードテーブルなし', method: 'vm_extract' };
  return {
    success: true, tables, method: 'vm_extract',
    hints: tables.map(t=>`${t.name}[${t.count}]: [${t.sample.join(',')}...]${t.isLikelyBytecode?' (bytecode候補)':''}`),
  };
}

module.exports = {
  extractVmTableNames, extractVmTable,
  extractWeredevConstPool, parseConstPoolBody,
  resolveConstPoolElement, detectIfConstPool,
  extractWeredevZAccessor, _wdEscapeRegex,
  extractIfJBlocks, _flattenIfJTree, _collectLeafStatements,
  _splitIfThenElse, _findIfBlockEnd, extractWeredevDispatchLoop,
  dumpBytecodeTables, vmBytecodeExtractor,
};
