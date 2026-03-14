// vm/weredevs/extractor.js
'use strict';

const { decodeLuaEscapes }  = require('../../core/stringDecoder');
const {
  weredevsDecode,
  buildVTable,
  detectWeredevsStructure,
  extractWeredevsGMap,
  weredevsCustomDecode,
  unshuffleFArray,
  decodeWeredevsFPool,
} = require('../../utils/stringPipeline');

// ────────────────────────────────────────────────────────────────────────
//  最初の LocalStatement の変数名を動的取得
// ────────────────────────────────────────────────────────────────────────
function extractFirstLocalName(code) {
  const m = code.match(/^\s*local\s+([A-Za-z_][A-Za-z0-9_]*)/m);
  return m ? m[1] : null;
}

function extractVmTableNames(code) {
  const names = [];
  const seen  = new Set();
  const re    = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const name = m[1];
    if (!seen.has(name)) { seen.add(name); names.push(name); }
  }
  return names;
}

function extractVmTable(code, vmTableName) {
  if (!vmTableName || !code) return null;
  code = decodeLuaEscapes(code);
  const startRe = new RegExp(
    'local\\s+' + vmTableName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*=\\s*\\{'
  );
  const startM = startRe.exec(code);
  if (!startM) return null;

  let depth = 0, pos = startM.index + startM[0].length - 1;
  const end = Math.min(code.length, pos + 200000);
  let tableEnd = -1;
  for (let i = pos; i < end; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') { depth--; if (depth === 0) { tableEnd = i; break; } }
  }
  if (tableEnd === -1) return null;

  const body = code.substring(pos + 1, tableEnd);
  const nums = body.split(',').map(s => {
    const t = s.trim().replace(/\s*--[^\n]*/g, '');
    return isNaN(Number(t)) ? null : Number(t);
  }).filter(n => n !== null);

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
    name: vmTableName, raw: body.substring(0, 500), nums,
    subTables: subTables.slice(0, 200), count: nums.length,
    isLikelyBytecode: nums.length >= 10 && Math.max(...nums.filter(n => typeof n === 'number')) < 65536,
  };
}

// ════════════════════════════════════════════════════════════════════════
//  extractWeredevConstPool — Weredevs定数プール完全デコード
//
//  【変更点】
//  旧実装はテーブル名を固定（"F", "R" など）または
//  buildVTable() の旧方式で抽出していたが、Weredevsは毎回テーブル名が
//  ランダムに変わるため、構造的特徴のみで検出するように変更。
//
//  処理フロー:
//    1. detectWeredevsStructure() でテーブル名・シャッフル情報を動的取得
//    2. decodeWeredevsFPool() で定数プールを完全デコード
//    3. 結果を { poolName → { name, elements, ... } } 形式で返す
// ════════════════════════════════════════════════════════════════════════
function extractWeredevConstPool(code) {
  try {
    // ── 新方式: 構造動的検出 + 完全デコード ──────────────────────────
    const fPoolResult = decodeWeredevsFPool(code);

    if (fPoolResult.success && fPoolResult.pool.length > 1) {
      const pools = {};

      // デコード済みpool[]を elements[] 形式に変換
      const elements = fPoolResult.pool.slice(1).map(s => {
        if (!s) return { type: 'nil', raw: '', value: null };
        const num = Number(s);
        if (!isNaN(num) && s.trim() !== '') return { type: 'number', raw: s, value: num };
        return { type: 'string', raw: s, value: s };
      });

      const strCount = elements.filter(e => e && e.type === 'string' && e.value.length > 0).length;

      // テーブル名: 動的解析で取得した poolName を使う、取れなければ 'F'
      const poolKey = fPoolResult.structure.poolName || 'F';

      pools[poolKey] = {
        name:             poolKey,
        elements,
        count:            elements.length,
        startPos:         0,
        endPos:           0,
        isLikelyConstPool: strCount >= 10,
        // デバッグ用メタ情報
        _decoded:         true,
        _gMap:            fPoolResult.gMap,
        _structure:       fPoolResult.structure,
        _meaningfulCount: fPoolResult.meaningfulCount,
      };

      return pools;
    }

    // ── フォールバック: 旧方式 ────────────────────────────────────────
    return _extractWeredevConstPoolLegacy(code);

  } catch (err) {
    console.error('[extractWeredevConstPool] error:', err.message);
    try { return _extractWeredevConstPoolLegacy(code); } catch {}
    return {};
  }
}

/**
 * 旧方式の定数プール抽出（フォールバック用）
 */
function _extractWeredevConstPoolLegacy(code) {
  try {
    const vtable = buildVTable(code);
    const workCode = decodeLuaEscapes(code);
    const pools = {};
    const tableRe = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{/g;
    let m;
    while ((m = tableRe.exec(workCode)) !== null) {
      const varName = m[1];
      const startPos = m.index + m[0].length - 1;
      let depth = 0, end = -1;
      const limit = Math.min(workCode.length, startPos + 2000000);
      for (let i = startPos; i < limit; i++) {
        if (workCode[i] === '{') depth++;
        else if (workCode[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
      }
      if (end === -1) continue;
      const body = workCode.substring(startPos + 1, end);
      const elements = parseConstPoolBody(body);
      if (elements.length < 1) continue;
      for (const el of elements) {
        if (el && el.type === 'string' && vtable) {
          const decoded = weredevsDecode(el.value, vtable);
          if (decoded !== el.value) el.value = decoded;
        }
      }
      pools[varName] = {
        name: varName, elements, count: elements.length,
        startPos: m.index, endPos: end + 1,
        isLikelyConstPool: detectIfConstPool(elements),
      };
    }
    return pools;
  } catch {
    return {};
  }
}

function parseConstPoolBody(body) {
  const elements = [];
  let i = 0, cur = '', depth = 0, inStr = false, strCh = '';
  while (i < body.length) {
    const c = body[i];
    if (!inStr) {
      if (c === '"' || c === "'") { inStr = true; strCh = c; cur += c; }
      else if (c === '[' && body[i+1] === '[') {
        let e = body.indexOf(']]', i + 2);
        if (e === -1) e = body.length - 2;
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
  if (cur.trim()) {
    const elem = resolveConstPoolElement(cur.trim());
    if (elem !== undefined) elements.push(elem);
  }
  return elements;
}

function resolveConstPoolElement(tok) {
  if (!tok) return undefined;
  const keyValM = tok.match(/^\s*\[\s*-?\d+\s*\]\s*=\s*(.+)$/s);
  if (keyValM) tok = keyValM[1].trim();
  if ((tok.startsWith('"') && tok.endsWith('"')) || (tok.startsWith("'") && tok.endsWith("'"))) {
    let value = tok.slice(1, -1)
      .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\r/g, '\r')
      .replace(/\\\\/g, '\\').replace(/\\"/g, '"').replace(/\\'/g, "'")
      .replace(/\\(\d{1,3})/g, (_, d) => String.fromCharCode(parseInt(d)))
      .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    value = decodeLuaEscapes(value);
    return { type: 'string', raw: tok, value };
  }
  if (tok.startsWith('[[') && tok.endsWith(']]')) return { type: 'string', raw: tok, value: tok.slice(2, -2) };
  if (tok === 'nil')   return { type: 'nil',  raw: tok, value: null };
  if (tok === 'true')  return { type: 'bool', raw: tok, value: true };
  if (tok === 'false') return { type: 'bool', raw: tok, value: false };
  const n = Number(tok.replace(/_/g, ''));
  if (!isNaN(n) && tok !== '') return { type: 'number', raw: tok, value: n };
  try {
    if (/^[\d\s+\-*/().\^%]+$/.test(tok)) {
      const v = Function('"use strict";return(' + tok + ')')();
      if (typeof v === 'number' && isFinite(v)) return { type: 'number', raw: tok, value: v };
    }
  } catch {}
  return { type: 'expr', raw: tok, value: tok };
}

function detectIfConstPool(elements) {
  if (elements.length === 0) return false;
  if (elements.length < 4) return true;
  const strCount = elements.filter(e => e && e.type === 'string').length;
  const numCount = elements.filter(e => e && e.type === 'number').length;
  return strCount >= 2 || numCount >= 10 || (strCount >= 1 && numCount >= 2) || elements.length >= 4;
}

// ────────────────────────────────────────────────────────────────────────
//  buildConstPoolArray
//  名前依存なし — _decoded フラグかつ最大要素数のプールを優先
// ────────────────────────────────────────────────────────────────────────
function buildConstPoolArray(constPools, code) {
  if (!constPools || Object.keys(constPools).length === 0) return [];

  // 新方式でデコード済みのプールを優先
  for (const pool of Object.values(constPools)) {
    if (pool._decoded) return pool.elements.map(e => e ? e.value : null);
  }

  // 旧方式: isLikelyConstPool=true で最大要素数
  let poolName = null, maxLikely = 0;
  for (const [name, pool] of Object.entries(constPools)) {
    if (pool.isLikelyConstPool && pool.count > maxLikely) {
      maxLikely = pool.count; poolName = name;
    }
  }
  if (!poolName) {
    let maxCount = 0;
    for (const [name, pool] of Object.entries(constPools)) {
      if (pool.count > maxCount) { maxCount = pool.count; poolName = name; }
    }
  }
  if (!poolName) return [];

  const vtable = buildVTable(code || '');
  return constPools[poolName].elements.map(e => {
    if (!e) return null;
    if (typeof e.value === 'string') return weredevsDecode(e.value, vtable);
    return e.value;
  });
}

// ────────────────────────────────────────────────────────────────────────
//  extractWeredevZAccessor — アクセサ関数の動的検出
//  テーブル名・関数名に依存せず構造で検出する
// ────────────────────────────────────────────────────────────────────────
function extractWeredevZAccessor(code, constPools) {
  const accessors = {};

  // detectWeredevsStructure で取得した accessorName を使う
  const structure = detectWeredevsStructure(code);
  if (structure.accessorName) {
    const poolName = structure.poolName || (constPools ? Object.keys(constPools)[0] : null);
    accessors[structure.accessorName] = {
      funcName:  structure.accessorName,
      poolName:  poolName,
      offset:    structure.accessorOffset,
      sign:      structure.accessorOffset < 0 ? '+' : '-',
      raw:       '',
    };
  }

  // 追加: 名前に依存しないパターンマッチ
  const patterns = [
    // local function <name>(<arg>) return <pool>[<arg> - (<expr>)] end
    /local\s+function\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*return\s+([A-Za-z_]\w*)\s*\[\s*\2\s*-\s*\(([-\d+*(). ]+)\)\s*\]\s*end/g,
    // local <name> = function(<arg>) return <pool>[<arg> - <expr>] end
    /local\s+([A-Za-z_]\w*)\s*=\s*function\s*\(\s*([A-Za-z_]\w*)\s*\)\s*return\s+([A-Za-z_]\w*)\s*\[\s*\2\s*([\+\-])\s*(\d+)\s*\]\s*end/g,
    // 引数をそのままインデックス
    /local\s+([A-Za-z_]\w*)\s*=\s*function\s*\(\s*([A-Za-z_]\w*)\s*\)\s*return\s+([A-Za-z_]\w*)\s*\[\s*\2\s*\]\s*end/g,
  ];

  for (const re of patterns) {
    let m; re.lastIndex = 0;
    while ((m = re.exec(code)) !== null) {
      const funcName = m[1];
      const poolRef  = m[3];
      if (accessors[funcName]) continue; // 既登録はスキップ
      // constPoolsにpoolRefが存在するか確認（存在しなければスキップ）
      if (constPools && !constPools[poolRef]) continue;

      let offset = 0, sign = '+';
      if (m[4] && m[5]) {
        sign   = m[4];
        offset = parseInt(m[5]) * (sign === '-' ? 1 : -1);
      } else if (m[4] && !m[5]) {
        // パターン1: offset式
        const v = Function('"use strict"; return (' + m[4].replace(/\+-/g, '-') + ')')();
        if (typeof v === 'number') offset = -v;
      }
      accessors[funcName] = { funcName, poolName: poolRef, offset, sign, raw: m[0] };
    }
  }

  return accessors;
}

function _wdEscapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractIfJBlocks(loopBody, jVar) {
  if (!jVar) {
    const m = loopBody.match(/\bif\s+([A-Za-z_]\w*)\s*[<>=!]/);
    jVar = m ? m[1] : 'J';
  }
  const blocks = [];
  _flattenIfJTree(loopBody, jVar, blocks);
  blocks.sort((a, b) => a.threshold - b.threshold);
  return blocks;
}

function _flattenIfJTree(src, jVar, out) {
  const ifRe = new RegExp(`\\bif\\s+${_wdEscapeRegex(jVar)}\\s*(<|<=|==|>=|>)\\s*(\\d+)\\s*then`);
  const m = ifRe.exec(src);
  if (!m) { _collectLeafStatements(src, jVar, out); return; }

  const threshold = parseInt(m[2]);
  const thenStart = m.index + m[0].length;
  const beforeIf  = src.substring(0, m.index).trim();
  if (beforeIf.length > 5) _collectLeafStatements(beforeIf, jVar, out, threshold - 0.5);

  const { thenBody, elseBody } = _splitIfThenElse(src, thenStart);
  const ifReThen = new RegExp(`\\bif\\s+${_wdEscapeRegex(jVar)}\\s*[<>=!]`);

  if (ifReThen.test(thenBody)) _flattenIfJTree(thenBody, jVar, out);
  else if (thenBody.trim().length > 0) out.push({ op: m[1], threshold, body: thenBody.trim(), pos: m.index, headerLen: m[0].length });

  if (elseBody && elseBody.trim().length > 0) {
    if (ifReThen.test(elseBody)) _flattenIfJTree(elseBody, jVar, out);
    else out.push({ op: '>=', threshold: threshold + 1, body: elseBody.trim(), pos: m.index + m[0].length });
  }

  const afterIf = _findIfBlockEnd(src, m.index);
  if (afterIf < src.length - 5) _flattenIfJTree(src.substring(afterIf), jVar, out);
}

function _collectLeafStatements(src, jVar, out, hintThreshold) {
  const trimmed = src.trim();
  if (!trimmed || trimmed.length < 3) return;
  if (/^--/.test(trimmed)) return;
  if (/\b(if|while|for|repeat)\b/.test(trimmed)) return;
  if (/^end\s*$/.test(trimmed)) return;
  out.push({ op: '<', threshold: Math.round(hintThreshold || 0) + 1, body: trimmed, pos: -1, headerLen: 0, isImplicitLeaf: true });
}

function _splitIfThenElse(src, thenStart) {
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
        if (elsePos !== -1) return { thenBody: src.substring(thenStart, elsePos), elseBody: src.substring(elsePos + 4, endPos) };
        return { thenBody: src.substring(thenStart, endPos), elseBody: '' };
      }
    } else if ((kw === 'else' || kw === 'elseif') && depth === 1) elsePos = km.index;
  }
  return { thenBody: src.substring(thenStart), elseBody: '' };
}

function _findIfBlockEnd(src, ifStart) {
  let depth = 0;
  const keywords = /\b(if|while|for|repeat|do|function)\b|\bend\b/g;
  keywords.lastIndex = ifStart;
  let m;
  while ((m = keywords.exec(src)) !== null) {
    if (/^(if|while|for|function|do|repeat)$/.test(m[0])) depth++;
    else if (m[0] === 'end') { depth--; if (depth === 0) return m.index + 3; }
  }
  return src.length;
}

function extractWeredevDispatchLoop(code) {
  try {
    const loops = [];
    const whileRe = /while\s+([A-Za-z_]\w*)\s+do\b/g;
    let m;
    while ((m = whileRe.exec(code)) !== null) {
      const loopVar = m[1];
      if (loopVar === 'true' || loopVar === '1') continue;
      const doIdx = code.indexOf('do', m.index + m[0].length - 3);
      if (doIdx === -1) continue;
      let depth = 1, end = -1, scan = doIdx + 2;
      const limit = Math.min(code.length, doIdx + 5000000);
      while (scan < limit) {
        const sub = code.slice(scan);
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
    const whileTrueRe = /while\s+true\s+do\b/g;
    while ((m = whileTrueRe.exec(code)) !== null) {
      const snippet = code.substring(m.index, Math.min(code.length, m.index + 500000));
      const blocks = extractIfJBlocks(snippet, null);
      if (blocks.length >= 3) {
        const jVarM = snippet.match(/if\s+([A-Za-z_]\w*)\s*[<>=!]/);
        const lv = jVarM ? jVarM[1] : 'J';
        loops.push({ loopVar: lv, loopStart: m.index, loopEnd: m.index + snippet.length, body: snippet, dispatchBlocks: blocks, blockCount: blocks.length, isWhileTrue: true });
      }
    }
    return loops;
  } catch { return []; }
}

function dumpBytecodeTables(code) {
  const candidates = [];
  const headerRe = /local\s+(\w+)\s*=\s*\{/g;
  let m;
  while ((m = headerRe.exec(code)) !== null) {
    const varName = m[1], openPos = m.index + m[0].length - 1;
    let depth = 0, closePos = -1;
    const limit = Math.min(code.length, openPos + 500000);
    for (let i = openPos; i < limit; i++) {
      if (code[i] === '{') depth++;
      else if (code[i] === '}') { depth--; if (depth === 0) { closePos = i; break; } }
    }
    if (closePos === -1) continue;
    const body = code.substring(openPos + 1, closePos);
    const nums = body.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
    if (nums.length >= 50) candidates.push({ name: varName, count: nums.length });
  }
  if (candidates.length === 0) return { code, injected: false, candidates: [] };
  let inject = '\n-- ══ YAJU Bytecode Dump ══\n';
  for (const c of candidates) {
    inject += `if type(${c.name})=="table" then\n  for __i,__v in ipairs(${c.name}) do\n    print("__BYTECODE__\\t${c.name}\\t"..tostring(__i).."\\t"..tostring(__v))\n  end\nend\n`;
  }
  return { code: code + inject, injected: true, candidates };
}

function vmBytecodeExtractor(code) {
  const tables = [];
  const headerRe = /local\s+(\w+)\s*=\s*\{/g;
  let m;
  while ((m = headerRe.exec(code)) !== null) {
    const varName = m[1], openPos = m.index + m[0].length - 1;
    let depth = 0, closePos = -1;
    const limit = Math.min(code.length, openPos + 500000);
    for (let i = openPos; i < limit; i++) {
      if (code[i] === '{') depth++;
      else if (code[i] === '}') { depth--; if (depth === 0) { closePos = i; break; } }
    }
    if (closePos === -1) continue;
    const body = code.substring(openPos + 1, closePos);
    const nums = body.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
    if (nums.length >= 10) {
      const max = Math.max(...nums);
      tables.push({ name: varName, count: nums.length, sample: nums.slice(0, 16), isLikelyBytecode: max < 65536 });
    }
  }
  if (tables.length === 0) return { success: false, error: 'バイトコードテーブルなし', method: 'vm_extract' };
  return {
    success: true, tables, method: 'vm_extract',
    hints: tables.map(t => `${t.name}[${t.count}]: [${t.sample.join(',')}...]${t.isLikelyBytecode ? ' (bytecode候補)' : ''}`),
  };
}

module.exports = {
  extractFirstLocalName,
  extractVmTableNames, extractVmTable,
  extractWeredevConstPool, parseConstPoolBody,
  resolveConstPoolElement, detectIfConstPool,
  buildConstPoolArray,
  extractWeredevZAccessor, _wdEscapeRegex,
  extractIfJBlocks, _flattenIfJTree, _collectLeafStatements,
  _splitIfThenElse, _findIfBlockEnd, extractWeredevDispatchLoop,
  dumpBytecodeTables, vmBytecodeExtractor,
};
