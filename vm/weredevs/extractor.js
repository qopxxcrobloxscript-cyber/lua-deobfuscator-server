// vm/weredevs/extractor.js
'use strict';

/**
 * VM bytecode table 名の動的検出。
 * Weredevs は難読化ごとにテーブル名を変えるため固定名解析は使わず、
 * /local\s+(\w+)\s*=\s*{/ で全ての local テーブル宣言を拾い、
 * 数値要素数・最大値から bytecode テーブル候補を絞り込む。
 *
 * @param {string} code
 * @param {object} [opts]
 * @param {boolean} [opts.allTables=false]  — true: フィルタなし全件返す
 * @param {number}  [opts.minNums=10]       — bytecode 候補と見なす最小数値要素数
 * @returns {string[]}  テーブル変数名の配列（検出順）
 */
function extractVmTableNames(code, opts) {
  const allTables = opts && opts.allTables;
  const minNums   = (opts && opts.minNums) || 10;

  // ── 段階1: /local\s+(\w+)\s*=\s*{/ で全テーブル宣言を列挙 ──────────
  const re    = /local\s+(\w+)\s*=\s*\{/g;
  const names = [];
  const seen  = new Set();
  let m;

  while ((m = re.exec(code)) !== null) {
    const name = m[1];
    if (seen.has(name)) continue;
    seen.add(name);

    if (allTables) { names.push(name); continue; }

    // ── 段階2: テーブル本体を取り出して数値要素数を数える ───────────
    const bodyStart = m.index + m[0].length - 1; // '{' の位置
    let depth = 0, end = -1;
    const limit = Math.min(code.length, bodyStart + 500_000);
    for (let i = bodyStart; i < limit; i++) {
      if (code[i] === '{') depth++;
      else if (code[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
    }
    if (end === -1) continue;

    const body = code.substring(bodyStart + 1, end);
    // 数値要素のみ抽出（コメント・文字列を除外する簡易計測）
    const nums = body.split(',').map(s => {
      const t = s.trim().replace(/\s*--[^\n]*/g, '');
      return isNaN(Number(t)) || t === '' ? null : Number(t);
    }).filter(n => n !== null);

    if (nums.length >= minNums) names.push(name);
  }

  return names;
}
function extractVmTable(code, vmTableName) {
  if (!vmTableName || !code) return null;
  const startRe = new RegExp('local\\s+' + vmTableName.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + '\\s*=\\s*\\{');
  const startM = startRe.exec(code);
  if (!startM) return null;
  let depth = 0, pos = startM.index + startM[0].length - 1;
  const end = Math.min(code.length, pos + 200000);
  let tableEnd = -1;
  for (let i = pos; i < end; i++) { if (code[i] === '{') depth++; else if (code[i] === '}') { depth--; if (depth === 0) { tableEnd = i; break; } } }
  if (tableEnd === -1) return null;
  const body = code.substring(pos + 1, tableEnd);
  const nums = body.split(',').map(s => { const t = s.trim().replace(/\s*--[^\n]*/g, ''); return isNaN(Number(t)) ? null : Number(t); }).filter(n => n !== null);
  const subTables = [];
  const subRe = /\{([^{}]+)\}/g; let sm;
  while ((sm = subRe.exec(body)) !== null) { const inner = sm[1].split(',').map(s => { const t = s.trim(); return isNaN(Number(t)) ? t : Number(t); }); subTables.push(inner); }
  return { name: vmTableName, raw: body.substring(0, 500), nums, subTables: subTables.slice(0, 200), count: nums.length, isLikelyBytecode: nums.length >= 10 && Math.max(...nums.filter(n=>typeof n==='number')) < 65536 };
}
function extractWeredevConstPool(code) {
  const pools = {};
  const tableRe = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{/g; let m;
  while ((m = tableRe.exec(code)) !== null) {
    const varName = m[1], startPos = m.index + m[0].length - 1;
    let depth = 0, pos = startPos, end = -1;
    const limit = Math.min(code.length, startPos + 2000000);
    for (let i = startPos; i < limit; i++) { if (code[i] === '{') depth++; else if (code[i] === '}') { depth--; if (depth === 0) { end = i; break; } } }
    if (end === -1) continue;
    const body = code.substring(startPos + 1, end);
    const elements = parseConstPoolBody(body);
    if (elements.length < 1) continue;
    pools[varName] = { name: varName, elements, count: elements.length, startPos: m.index, endPos: end + 1, isLikelyConstPool: detectIfConstPool(elements) };
  }
  return pools;
}
function parseConstPoolBody(body) {
  const elements = []; let i = 0, cur = '', depth = 0, inStr = false, strCh = '';
  while (i < body.length) {
    const c = body[i];
    if (!inStr) {
      if (c === '"' || c === "'") { inStr = true; strCh = c; cur += c; }
      else if (c === '[' && body[i+1] === '[') { let e = body.indexOf(']]', i + 2); if (e === -1) e = body.length - 2; cur += body.substring(i, e + 2); i = e + 2; continue; }
      else if (c === '{') { depth++; cur += c; }
      else if (c === '}') { depth--; cur += c; }
      else if (c === ',' && depth === 0) { const elem = resolveConstPoolElement(cur.trim()); if (elem !== undefined) elements.push(elem); cur = ''; }
      else cur += c;
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
    return { type: 'string', raw: tok, value: tok.slice(1,-1).replace(/\\n/g,'\n').replace(/\\t/g,'\t').replace(/\\r/g,'\r').replace(/\\\\/g,'\\').replace(/\\"/g,'"').replace(/\\'/g,"'").replace(/\\(\d{1,3})/g,(_,d)=>String.fromCharCode(parseInt(d))).replace(/\\x([0-9a-fA-F]{2})/g,(_,h)=>String.fromCharCode(parseInt(h,16))) };
  }
  if (tok.startsWith('[[') && tok.endsWith(']]')) return { type:'string', raw:tok, value:tok.slice(2,-2) };
  if (tok === 'nil')   return { type:'nil',  raw:tok, value:null };
  if (tok === 'true')  return { type:'bool', raw:tok, value:true };
  if (tok === 'false') return { type:'bool', raw:tok, value:false };
  const n = Number(tok.replace(/_/g,''));
  if (!isNaN(n) && tok !== '') return { type:'number', raw:tok, value:n };
  try { if (/^[\d\s+\-*/().\^%]+$/.test(tok)) { const v = Function('"use strict";return('+tok+')')(); if (typeof v==='number' && isFinite(v)) return { type:'number', raw:tok, value:v }; } } catch {}
  return { type:'expr', raw:tok, value:tok };
}
function detectIfConstPool(elements) {
  if (elements.length === 0) return false;
  if (elements.length < 4) return true;
  const strCount = elements.filter(e => e && e.type === 'string').length;
  const numCount = elements.filter(e => e && e.type === 'number').length;
  return strCount >= 2 || numCount >= 10 || (strCount >= 1 && numCount >= 2) || elements.length >= 4;
}
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
      const funcName = m[1], poolName = m[3], sign = m[4] || '+', rawOffset = m[5] ? parseInt(m[5]) : 0;
      const offset = sign === '-' ? rawOffset : -rawOffset;
      if (constPools && (constPools[poolName] !== undefined)) accessors[funcName] = { funcName, poolName, offset, sign, raw: m[0] };
      else if (!constPools) accessors[funcName] = { funcName, poolName, offset, sign, raw: m[0] };
    }
  }
  return accessors;
}
function _wdEscapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function extractIfJBlocks(loopBody, jVar) {
  if (!jVar) { const m = loopBody.match(/\bif\s+([A-Za-z_]\w*)\s*[<>=!]/); jVar = m ? m[1] : 'J'; }
  const blocks = [];
  _flattenIfJTree(loopBody, jVar, blocks);
  blocks.sort((a, b) => a.threshold - b.threshold);
  return blocks;
}
function _flattenIfJTree(src, jVar, out) {
  const ifRe = new RegExp(`\\bif\\s+${_wdEscapeRegex(jVar)}\\s*(<|<=|==|>=|>)\\s*(\\d+)\\s*then`);
  const m = ifRe.exec(src);
  if (!m) { _collectLeafStatements(src, jVar, out); return; }
  const op = m[1], threshold = parseInt(m[2]), thenStart = m.index + m[0].length;
  const beforeIf = src.substring(0, m.index).trim();
  if (beforeIf.length > 5) _collectLeafStatements(beforeIf, jVar, out, threshold - 0.5);
  const { thenBody, elseBody } = _splitIfThenElse(src, thenStart);
  const ifReThen = new RegExp(`\\bif\\s+${_wdEscapeRegex(jVar)}\\s*[<>=!]`);
  if (ifReThen.test(thenBody)) _flattenIfJTree(thenBody, jVar, out);
  else if (thenBody.trim().length > 0) out.push({ op, threshold, body: thenBody.trim(), pos: m.index, headerLen: m[0].length });
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
  let depth = 1; let elsePos = -1;
  const keywords = /\b(if|while|for|repeat|do|function)\b|\b(end|until)\b|\belse(?:if)?\b/g;
  keywords.lastIndex = thenStart;
  let km;
  while ((km = keywords.exec(src)) !== null) {
    const kw = km[0];
    if (/^(if|while|for|function|do|repeat)$/.test(kw)) depth++;
    else if (kw === 'end' || kw === 'until') { depth--; if (depth === 0) { const endPos = km.index; if (elsePos !== -1) return { thenBody: src.substring(thenStart, elsePos), elseBody: src.substring(elsePos + 4, endPos) }; return { thenBody: src.substring(thenStart, endPos), elseBody: '' }; } }
    else if ((kw === 'else' || kw === 'elseif') && depth === 1) elsePos = km.index;
  }
  return { thenBody: src.substring(thenStart), elseBody: '' };
}
function _findIfBlockEnd(src, ifStart) {
  let depth = 0;
  const keywords = /\b(if|while|for|repeat|do|function)\b|\bend\b/g;
  keywords.lastIndex = ifStart;
  let m;
  while ((m = keywords.exec(src)) !== null) { if (/^(if|while|for|function|do|repeat)$/.test(m[0])) depth++; else if (m[0] === 'end') { depth--; if (depth === 0) return m.index + 3; } }
  return src.length;
}
function extractWeredevDispatchLoop(code) {
  const loops = [];
  const whileRe = /while\s+([A-Za-z_]\w*)\s+do\b/g; let m;
  while ((m = whileRe.exec(code)) !== null) {
    const loopVar = m[1];
    if (loopVar === 'true' || loopVar === '1') continue;
    const doIdx = code.indexOf('do', m.index + m[0].length - 3);
    if (doIdx === -1) continue;
    let depth = 1, end = -1, scan = doIdx + 2;
    const limit = Math.min(code.length, doIdx + 5000000);
    while (scan < limit) {
      const sub = code.slice(scan);
      const nextDo = sub.search(/\b(do|then|repeat)\b/), nextEnd = sub.search(/\bend\b/);
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
}
function dumpBytecodeTables(code) {
  const candidates = [];
  const tblPat = /local\s+(\w+)\s*=\s*\{([\s\d,]+)\}/g; let m;
  while ((m = tblPat.exec(code)) !== null) { const nums = m[2].split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)); if (nums.length >= 50) candidates.push({ name: m[1], count: nums.length }); }
  if (candidates.length === 0) return { code, injected: false, candidates: [] };
  let inject = '\n-- ══ YAJU Bytecode Dump ══\n';
  for (const c of candidates) inject += `if type(${c.name})=="table" then\n  for __i,__v in ipairs(${c.name}) do\n    print("__BYTECODE__\\t${c.name}\\t"..tostring(__i).."\\t"..tostring(__v))\n  end\nend\n`;
  return { code: code + inject, injected: true, candidates };
}
function vmBytecodeExtractor(code) {
  const tables = [];
  const tblPattern = /local\s+(\w+)\s*=\s*\{((?:\s*\d+\s*,){10,}[^}]*)\}/g; let m;
  while ((m = tblPattern.exec(code)) !== null) {
    const name = m[1], nums = m[2].split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
    if (nums.length >= 10) { const max = Math.max(...nums); tables.push({ name, count: nums.length, sample: nums.slice(0,16), isLikelyBytecode: max < 65536 }); }
  }
  if (tables.length === 0) return { success: false, error: 'バイトコードテーブルなし', method: 'vm_extract' };
  return { success: true, tables, method: 'vm_extract', hints: tables.map(t=>`${t.name}[${t.count}]: [${t.sample.join(',')}...]${t.isLikelyBytecode?' (bytecode候補)':''}`) };
}
module.exports = { extractVmTableNames, extractVmTable, extractWeredevConstPool, parseConstPoolBody, resolveConstPoolElement, detectIfConstPool, extractWeredevZAccessor, _wdEscapeRegex, extractIfJBlocks, _flattenIfJTree, _collectLeafStatements, _splitIfThenElse, _findIfBlockEnd, extractWeredevDispatchLoop, dumpBytecodeTables, vmBytecodeExtractor };
