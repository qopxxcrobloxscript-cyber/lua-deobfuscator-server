// vm/weredevs/interpreterParser.js
'use strict';

const { _wdEscapeRegex } = require('./extractor');
const { LUA51_OPCODES, _inferOpNameFromOperands } = require('./opcodeMap');

function detectVmDispatchLoop(code) {
  const patterns = [
    { re: /while\s+true\s+do\b/,                        label: 'while true do' },
    { re: /while\s+1\s+do\b/,                           label: 'while 1 do' },
    { re: /while\s+true\s+do[\s\S]{0,60}local\s+l\s*=/, label: 'while true do + local l=' },
    { re: /repeat[\s\S]{0,200}until\s+false/,           label: 'repeat..until false' },
  ];
  const found = [];
  for (const p of patterns) {
    if (p.re.test(code)) {
      // ループ本体を少し抽出
      const m = p.re.exec(code);
      const snippet = code.substring(m.index, m.index + 200).replace(/\n/g, ' ');
      found.push({ label: p.label, pos: m.index, snippet });
    }
  }
  return { found, isVmDispatch: found.length > 0 };
}

// 項目 6: vmDecompileInstruction — 単一 opcode を Lua コードへ変換
// vmDecompiler の命令生成ロジックを単体関数として公開
function detectWeredevContext(code) {
  const ctx = { loopVar:'J', regVar:'V', pcVar:'pc', poolVar:'R', zFunc:'Z', instrVar:'I', stackVar:'S' };
  // loopVar
  const wvc = {};
  const wRe = /\bwhile\s+([A-Za-z_]\w*)\s+do\b/g;
  let m;
  while ((m = wRe.exec(code)) !== null) wvc[m[1]] = (wvc[m[1]]||0) + 1;
  delete wvc['true'];
  const lve = Object.entries(wvc).sort((a,b)=>b[1]-a[1]);
  if (lve.length > 0) ctx.loopVar = lve[0][0];
  // regVar (テーブル代入頻度)
  const tac = {};
  const taRe = /\b([A-Za-z_]\w*)\s*\[[^\]]+\]\s*=/g;
  while ((m = taRe.exec(code)) !== null) tac[m[1]] = (tac[m[1]]||0) + 1;
  const rc = Object.entries(tac)
    .filter(([k]) => k !== ctx.poolVar && !['string','table','math'].includes(k))
    .sort((a,b)=>b[1]-a[1]);
  if (rc.length > 0) ctx.regVar = rc[0][0];
  // zFunc / poolVar
  const zRe = /local\s+([A-Za-z_]\w*)\s*=\s*function\s*\([^)]+\)\s*return\s+([A-Za-z_]\w*)\s*\[/g;
  while ((m = zRe.exec(code)) !== null) { ctx.zFunc = m[1]; ctx.poolVar = m[2]; break; }
  // pcVar
  const pcc = {};
  const pcRe = /\b([A-Za-z_]\w*)\s*=\s*\1\s*\+\s*1\b/g;
  while ((m = pcRe.exec(code)) !== null) {
    const vn = m[1];
    if (vn !== ctx.loopVar && vn !== ctx.regVar) pcc[vn] = (pcc[vn]||0) + 1;
  }
  const pce = Object.entries(pcc).sort((a,b)=>b[1]-a[1]);
  if (pce.length > 0) ctx.pcVar = pce[0][0];
  return ctx;
}

// ────────────────────────────────────────────────────────────────────────
//  Step 7: Z(N) 呼び出しを定数値に解決
// ────────────────────────────────────────────────────────────────────────
function analyzeWeredevOpcodeBlock(block, ctx) {
  const body     = block.body;
  const regName  = (ctx && ctx.regVar)   || 'V';
  const pcName   = (ctx && ctx.pcVar)    || 'pc';
  const poolName = (ctx && ctx.poolVar)  || 'R';
  const zName    = (ctx && ctx.zFunc)    || 'Z';
  const ops = [];
  const rE = _wdEscapeRegex;

  // MOVE/LOADK
  const moveRe = new RegExp(
    `${rE(regName)}\\s*\\[([^\\]]+)\\]\\s*=\\s*` +
    `(?:${rE(regName)}\\s*\\[([^\\]]+)\\]|${rE(zName)}\\s*\\(([^)]+)\\)|${rE(poolName)}\\s*\\[([^\\]]+)\\])`, 'g');
  let mm;
  while ((mm = moveRe.exec(body)) !== null) {
    const dest = mm[1].trim();
    if (mm[2])      ops.push({ kind:'MOVE',  lua:`V[${dest}] = V[${mm[2].trim()}]` });
    else if (mm[3]) ops.push({ kind:'LOADK', lua:`V[${dest}] = Z(${mm[3].trim()})` });
    else if (mm[4]) ops.push({ kind:'LOADK', lua:`V[${dest}] = R[${mm[4].trim()}]` });
  }
  // 算術
  const arithRe = new RegExp(
    `${rE(regName)}\\s*\\[([^\\]]+)\\]\\s*=\\s*` +
    `${rE(regName)}\\s*\\[([^\\]]+)\\]\\s*([+\\-*/%^])\\s*${rE(regName)}\\s*\\[([^\\]]+)\\]`, 'g');
  while ((mm = arithRe.exec(body)) !== null) {
    const sym = mm[3];
    const name = {'+':'ADD','-':'SUB','*':'MUL','/':'DIV','%':'MOD','^':'POW'}[sym]||'ARITH';
    ops.push({ kind:name, lua:`V[${mm[1].trim()}] = V[${mm[2].trim()}] ${sym} V[${mm[4].trim()}]` });
  }
  // NEWTABLE
  const ntRe = new RegExp(`${rE(regName)}\\s*\\[([^\\]]+)\\]\\s*=\\s*\\{\\s*\\}`, 'g');
  while ((mm = ntRe.exec(body)) !== null) ops.push({ kind:'NEWTABLE', lua:`V[${mm[1].trim()}] = {}` });
  // GETTABLE
  const gtRe = new RegExp(
    `${rE(regName)}\\s*\\[([^\\]]+)\\]\\s*=\\s*${rE(regName)}\\s*\\[([^\\]]+)\\]\\s*\\[([^\\]]+)\\]`, 'g');
  while ((mm = gtRe.exec(body)) !== null)
    ops.push({ kind:'GETTABLE', lua:`V[${mm[1].trim()}] = V[${mm[2].trim()}][${mm[3].trim()}]` });
  // SETTABLE
  const stRe = new RegExp(
    `${rE(regName)}\\s*\\[([^\\]]+)\\]\\s*\\[([^\\]]+)\\]\\s*=\\s*${rE(regName)}\\s*\\[([^\\]]+)\\]`, 'g');
  while ((mm = stRe.exec(body)) !== null)
    ops.push({ kind:'SETTABLE', lua:`V[${mm[1].trim()}][${mm[2].trim()}] = V[${mm[3].trim()}]` });
  // CONCAT
  const catRe = new RegExp(
    `${rE(regName)}\\s*\\[([^\\]]+)\\]\\s*=\\s*${rE(regName)}\\s*\\[([^\\]]+)\\]\\s*\\.\\.\\s*${rE(regName)}\\s*\\[([^\\]]+)\\]`, 'g');
  while ((mm = catRe.exec(body)) !== null)
    ops.push({ kind:'CONCAT', lua:`V[${mm[1].trim()}] = V[${mm[2].trim()}] .. V[${mm[3].trim()}]` });
  // UNM/NOT/LEN
  const unRe = new RegExp(
    `${rE(regName)}\\s*\\[([^\\]]+)\\]\\s*=\\s*([-#]|not\\s+)${rE(regName)}\\s*\\[([^\\]]+)\\]`, 'g');
  while ((mm = unRe.exec(body)) !== null) {
    const s = mm[2].trim();
    const n = s==='-'?'UNM':s==='#'?'LEN':'NOT';
    ops.push({ kind:n, lua:`V[${mm[1].trim()}] = ${s}V[${mm[3].trim()}]` });
  }
  // CALL
  const callRe = new RegExp(`${rE(regName)}\\s*\\[([^\\]]+)\\]\\s*\\(([^)]*)\\)`, 'g');
  while ((mm = callRe.exec(body)) !== null)
    ops.push({ kind:'CALL', lua:`V[${mm[1].trim()}](${mm[2].trim()})` });
  // JMP
  const jmpRe = new RegExp(`${rE(pcName)}\\s*=\\s*${rE(pcName)}\\s*([+\\-])\\s*(\\d+)`, 'g');
  while ((mm = jmpRe.exec(body)) !== null) {
    const delta = mm[1]==='+'?parseInt(mm[2]):-parseInt(mm[2]);
    ops.push({ kind:'JMP', lua:`-- jump pc${delta>=0?'+':''}${delta}`, delta });
  }
  // COND_JMP
  const condRe = new RegExp(`if\\s+(?:not\\s+)?${rE(regName)}\\s*\\[([^\\]]+)\\]`, 'g');
  while ((mm = condRe.exec(body)) !== null)
    ops.push({ kind:'COND_JMP', lua:`if V[${mm[1].trim()}] then ... end` });
  // RETURN
  if (/\breturn\b/.test(body) && !/function/.test(body)) {
    const rm = body.match(/return\s+(.+)/s);
    ops.push({ kind:'RETURN', lua: rm ? `return ${rm[1].trim().substring(0,120).replace(/\n/g,' ')}` : 'return' });
  }
  // GETGLOBAL
  const ggRe = /(?:_ENV|_G)\s*\[([^\]]+)\]/g;
  while ((mm = ggRe.exec(body)) !== null)
    ops.push({ kind:'GETGLOBAL', lua:`-- GETGLOBAL _G[${mm[1].trim()}]` });
  if (ops.length === 0)
    ops.push({ kind:'RAW', lua:`-- [raw] ${body.substring(0,120).replace(/\n/g,' ')}` });
  return ops;
}

// ────────────────────────────────────────────────────────────────────────
//  Step 6: コンテキスト変数名の自動検出
// ────────────────────────────────────────────────────────────────────────
function extractWeredevOperands(body, ctx) {
  const rV   = (ctx && ctx.regVar)  || 'V';
  const zFn  = (ctx && ctx.zFunc)   || 'Z';
  const rE   = _wdEscapeRegex;
  let m;

  // ARITH: V[A] = V[B] OP V[C]  (MOVEより先に評価)
  m = body.match(new RegExp(`${rE(rV)}\\s*\\[(\\d+)\\]\\s*=\\s*${rE(rV)}\\s*\\[(\\d+)\\]\\s*([+\\-*/%^])\\s*${rE(rV)}\\s*\\[(\\d+)\\]`));
  if (m) return { A: parseInt(m[1]), B: parseInt(m[2]), C: parseInt(m[4]), _op: m[3] };

  // CONCAT: V[A] = V[B] .. V[C]
  m = body.match(new RegExp(`${rE(rV)}\\s*\\[(\\d+)\\]\\s*=\\s*${rE(rV)}\\s*\\[(\\d+)\\]\\s*\\.\\s*\\.\\s*${rE(rV)}\\s*\\[(\\d+)\\]`));
  if (m) return { A: parseInt(m[1]), B: parseInt(m[2]), C: parseInt(m[3]) };

  // GETTABLE: V[A] = V[B][V[C] or Z(x) or literal]
  m = body.match(new RegExp(`${rE(rV)}\\s*\\[(\\d+)\\]\\s*=\\s*${rE(rV)}\\s*\\[(\\d+)\\]\\s*\\[(?:${rE(rV)}\\s*\\[(\\d+)\\]|${rE(zFn)}\\s*\\((\\d+)\\)|(\\d+))\\]`));
  if (m) return { A: parseInt(m[1]), B: parseInt(m[2]), C: m[3]!=null?parseInt(m[3]):m[4]!=null?parseInt(m[4]):m[5]!=null?parseInt(m[5]):null };

  // SETTABLE: V[A][key] = V[C]
  m = body.match(new RegExp(`${rE(rV)}\\s*\\[(\\d+)\\]\\s*\\[(?:${rE(rV)}\\s*\\[(\\d+)\\]|${rE(zFn)}\\s*\\((\\d+)\\))\\]\\s*=\\s*${rE(rV)}\\s*\\[(\\d+)\\]`));
  if (m) return { A: parseInt(m[1]), B: m[2]!=null?parseInt(m[2]):m[3]!=null?parseInt(m[3]):null, C: parseInt(m[4]) };

  // UNM/NOT/LEN: V[A] = -/not/# V[B]
  m = body.match(new RegExp(`${rE(rV)}\\s*\\[(\\d+)\\]\\s*=\\s*(?:-|not\\s+|#)${rE(rV)}\\s*\\[(\\d+)\\]`));
  if (m) return { A: parseInt(m[1]), B: parseInt(m[2]), C: null };

  // LOADK: V[A] = Z(B)
  m = body.match(new RegExp(`${rE(rV)}\\s*\\[(\\d+)\\]\\s*=\\s*${rE(zFn)}\\s*\\((\\d+)\\)`));
  if (m) return { A: parseInt(m[1]), B: parseInt(m[2]), C: null };

  // NEWTABLE: V[A] = {}
  m = body.match(new RegExp(`${rE(rV)}\\s*\\[(\\d+)\\]\\s*=\\s*\\{\\s*\\}`));
  if (m) return { A: parseInt(m[1]), B: 0, C: 0 };

  // RETURN: return V[A], ...
  m = body.match(new RegExp(`return\\s+${rE(rV)}\\s*\\[(\\d+)\\]`));
  if (m) {
    const nret = (body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]`, 'g')) || []).length;
    return { A: parseInt(m[1]), B: nret + 1, C: null };
  }
  if (/\breturn\b/.test(body) && !/function/.test(body)) return { A: 0, B: 1, C: null };

  // CALL: V[A](...)
  m = body.match(new RegExp(`${rE(rV)}\\s*\\[(\\d+)\\]\\s*\\(`));
  if (m) return { A: parseInt(m[1]), B: null, C: null };

  // MOVE: V[A] = V[B]  (最後 - 他パターンと誤マッチを防ぐ)
  m = body.match(new RegExp(`${rE(rV)}\\s*\\[(\\d+)\\]\\s*=\\s*${rE(rV)}\\s*\\[(\\d+)\\](?!\\s*[+\\-*/%^\\[\\.])`));
  if (m) return { A: parseInt(m[1]), B: parseInt(m[2]), C: null };

  return { A: null, B: null, C: null };
}

// ── 補助: instrLua内の K[N] をフラット定数プールの値で置換 ──────────────
function _buildFlatConstPool(constPools, accessors) {
  // アクセサごとに { funcName → [elem0, elem1, ...] (0-indexed, offset適用済み) }
  const flat = {};
  for (const [fn, acc] of Object.entries(accessors)) {
    const pool = constPools[acc.poolName];
    if (!pool) continue;
    // Z(i) → pool.elements[i - offset - 1]  (1-indexed)
    flat[fn] = { elements: pool.elements, offset: acc.offset };
  }
  return flat;
}

// ── 補助: ブロック本体からLua5.1形式のA/B/Cオペランドを推定抽出 ─────────
function resolveWeredevZCalls(code, accessors, constPools) {
  if (!accessors || Object.keys(accessors).length === 0) return { code, resolved: 0 };
  let modified = code, resolved = 0;
  for (const [funcName, accessor] of Object.entries(accessors)) {
    const pool = constPools[accessor.poolName];
    if (!pool) continue;
    const callRe = new RegExp(`\\b${_wdEscapeRegex(funcName)}\\s*\\(\\s*(\\d+)\\s*\\)`, 'g');
    modified = modified.replace(callRe, (match, idxStr) => {
      const idx = parseInt(idxStr);
      // Z(i) = R[i - offset]  ここでoffsetはLuaの1-indexed基準
      // JS配列は0-indexed なので: elements[R-index - 1]
      // R-index = idx - offset  →  JS-index = R-index - 1 = idx - offset - 1
      // ただしoffsetが既に「Luaインデックスの調整値」なので:
      //   Z(i) = R[i - offset] なら R-index = i - offset, JS-index = i - offset - 1
      const jsIdx = idx - accessor.offset - 1;
      const elem = pool.elements[jsIdx];
      if (!elem) return match;
      resolved++;
      if (elem.type === 'string') {
        const safe = elem.value.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n').replace(/\r/g,'\\r');
        return `"${safe}"`;
      }
      if (elem.type === 'number') return String(elem.value);
      if (elem.type === 'bool')   return String(elem.value);
      if (elem.type === 'nil')    return 'nil';
      return match;
    });
  }
  return { code: modified, resolved };
}

// ────────────────────────────────────────────────────────────────────────
//  コード後処理
// ────────────────────────────────────────────────────────────────────────

module.exports = {
  detectVmDispatchLoop, detectWeredevContext,
  analyzeWeredevOpcodeBlock, extractWeredevOperands,
  _buildFlatConstPool, resolveWeredevZCalls,
};
