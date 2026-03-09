// core/stringDecoder.js
'use strict';

const { parseLuaArrayElements, resolveLuaStringEscapes, stripLuaString,
         splitByComma, splitByConcat, hashCode } = require('../utils/luaPrinter');

class CapturePool {
  constructor() { this.entries = []; }
  add(code, source) {
    if (code && code.length > 5 && !this.entries.some(e => e.code === code))
      this.entries.push({ code, source, ts: Date.now() });
  }
  getLuaCandidates() {
    return this.entries
      .filter(e => scoreLuaCode(e.code) > 20)
      .sort((a, b) => scoreLuaCode(b.code) - scoreLuaCode(a.code));
  }
  getBest() {
    const cands = this.getLuaCandidates();
    return cands.length ? cands[0].code : null;
  }
}

// ────────────────────────────────────────────────────────────────────────
//  共通ユーティリティ  (v2から引継ぎ + 拡張)
// ────────────────────────────────────────────────────────────────────────

class SymbolicEnv {
  constructor(parent=null){ this.vars=new Map(); this.parent=parent; }
  get(name){ if(this.vars.has(name))return this.vars.get(name); if(this.parent)return this.parent.get(name); return null; }
  set(name,entry){ this.vars.set(name,entry); }
  child(){ return new SymbolicEnv(this); }
}

function evalLuaNumExpr(expr) {
  const src=(expr||'').trim(); if (!src) return null;
  let pos=0;
  const peek=()=>pos<src.length?src[pos]:'';
  const consume=()=>pos<src.length?src[pos++]:'';
  const skipWs=()=>{ while(pos<src.length&&/\s/.test(src[pos]))pos++; };
  function parseExpr(){ return parseAddSub(); }
  function parseAddSub(){
    let l=parseMulDiv(); if(l===null)return null; skipWs();
    while(peek()==='+' || peek()==='-'){
      const op=consume(); skipWs(); const r=parseMulDiv(); if(r===null)return null;
      l=op==='+'?l+r:l-r; skipWs();
    }
    return l;
  }
  function parseMulDiv(){
    let l=parsePow(); if(l===null)return null; skipWs();
    while(peek()==='*'||peek()==='/'||peek()==='%'){
      const op=consume(); skipWs(); const r=parsePow(); if(r===null)return null;
      if(op==='*')l=l*r;
      else if(op==='/'){if(r===0)return null; l=Math.floor(l/r);}
      else{if(r===0)return null; l=((l%r)+r)%r;}
      skipWs();
    }
    return l;
  }
  function parsePow(){
    let b=parseUnary(); if(b===null)return null; skipWs();
    if(peek()==='^'){ consume(); skipWs(); const e=parseUnary(); if(e===null)return null; b=Math.pow(b,e); }
    return b;
  }
  function parseUnary(){
    skipWs();
    if(peek()==='-'){ consume(); skipWs(); const v=parseAtom(); return v===null?null:-v; }
    if(peek()==='+') consume();
    return parseAtom();
  }
  function parseAtom(){
    skipWs();
    if(peek()==='('){ consume(); const v=parseExpr(); skipWs(); if(peek()===')') consume(); return v; }
    if(src.startsWith('math.',pos)){
      pos+=5; let fname='';
      while(pos<src.length&&/[a-z]/.test(src[pos])) fname+=src[pos++];
      skipWs(); if(peek()!=='(') return null; consume();
      const args=[]; skipWs();
      while(peek()!==')'&&pos<src.length){ const a=parseExpr(); if(a===null)return null; args.push(a); skipWs(); if(peek()===','){consume();skipWs();} }
      if(peek()===')') consume();
      if(fname==='floor') return Math.floor(args[0]??0);
      if(fname==='ceil')  return Math.ceil(args[0]??0);
      if(fname==='abs')   return Math.abs(args[0]??0);
      if(fname==='max')   return args.length?Math.max(...args):null;
      if(fname==='min')   return args.length?Math.min(...args):null;
      if(fname==='sqrt')  return Math.sqrt(args[0]??0);
      return null;
    }
    if(src[pos]==='0'&&(src[pos+1]==='x'||src[pos+1]==='X')){
      pos+=2; let h='';
      while(pos<src.length&&/[0-9a-fA-F]/.test(src[pos])) h+=src[pos++];
      const n=parseInt(h,16); return isNaN(n)?null:n;
    }
    let numStr='';
    while(pos<src.length&&/[0-9.]/.test(src[pos])) numStr+=src[pos++];
    if(numStr===''||numStr==='.') return null;
    const n=parseFloat(numStr); return isNaN(n)?null:n;
  }
  try {
    const result=parseExpr(); skipWs();
    if(result===null||!isFinite(result)) return null;
    if(pos<src.length) return null;
    return result;
  } catch { return null; }
}
function evalSimpleExpr(expr) {
  try {
    const clean = expr.trim();
    if (!/^[\d\s+\-*/%().]+$/.test(clean)) return null;
    const result = Function('"use strict"; return (' + clean + ')')();
    if (typeof result === 'number' && isFinite(result)) return Math.floor(result);
    return null;
  } catch { return null; }
}

// ────────────────────────────────────────────────────────────────────────
//  SymbolicEnv  (v2から引継ぎ)
// ────────────────────────────────────────────────────────────────────────
function evalStringChar(argsStr,env) {
  const args=splitByComma(argsStr); const chars=[];
  for(const a of args){
    const val=evalExprWithEnv(a.trim(),env);
    if(val===null||typeof val!=='number') return null;
    const code=Math.round(val); if(code<0||code>255) return null;
    chars.push(String.fromCharCode(code));
  }
  return chars.join('');
}
function evalArithWithEnv(expr,env){
  if(!env) return evalLuaNumExpr(expr);
  let resolved=expr.replace(/\b([a-zA-Z_]\w*)\b/g,(m)=>{
    if(/^(math)$/.test(m)) return m;
    const entry=env?env.get(m):null;
    if(entry&&entry.type==='num') return String(entry.value);
    return m;
  });
  if(/[a-zA-Z_]/.test(resolved.replace(/math\./g,''))) return null;
  return evalLuaNumExpr(resolved);
}
function evalExprWithEnv(expr,env){
  if(!expr) return null; expr=expr.trim();
  const strVal=stripLuaString(expr); if(strVal!==null) return strVal;
  if(expr==='true') return 1; if(expr==='false'||expr==='nil') return 0;
  if(/^[\d\s\+\-\*\/\%\(\)\.\^x0-9a-fA-FxX]+$/.test(expr)||/^[\-\+]?\s*math\./.test(expr)){
    const n=evalLuaNumExpr(expr); if(n!==null) return n;
  }
  const scMatch=expr.match(/^string\.char\((.+)\)$/s);
  if(scMatch) return evalStringChar(scMatch[1],env);
  const tsMatch=expr.match(/^tostring\((.+)\)$/s);
  if(tsMatch){ const v=evalExprWithEnv(tsMatch[1],env); if(v!==null) return String(v); }
  const tnMatch=expr.match(/^tonumber\((.+?)(?:,\s*(\d+))?\)$/s);
  if(tnMatch){
    const v=evalExprWithEnv(tnMatch[1],env);
    if(typeof v==='string'){ const base=tnMatch[2]?parseInt(tnMatch[2]):10; const n=parseInt(v,base); if(!isNaN(n)) return n; }
    if(typeof v==='number') return v;
  }
  const repMatch=expr.match(/^string\.rep\((.+?),\s*(\d+)\)$/s);
  if(repMatch){ const s=evalExprWithEnv(repMatch[1],env); const n=parseInt(repMatch[2]); if(typeof s==='string'&&!isNaN(n)) return s.repeat(n); }
  const subMatch=expr.match(/^string\.sub\((.+?),\s*(-?\d+)(?:,\s*(-?\d+))?\)$/s);
  if(subMatch){
    const s=evalExprWithEnv(subMatch[1],env);
    if(typeof s==='string'){
      let i=parseInt(subMatch[2]),j=subMatch[3]!==undefined?parseInt(subMatch[3]):s.length;
      if(i<0) i=Math.max(0,s.length+i+1); if(j<0) j=s.length+j+1;
      return s.slice(i-1,j);
    }
  }
  const revMatch=expr.match(/^string\.reverse\((.+)\)$/s);
  if(revMatch){ const s=evalExprWithEnv(revMatch[1],env); if(typeof s==='string') return s.split('').reverse().join(''); }
  const byteMatch=expr.match(/^string\.byte\((.+?),\s*(\d+)(?:,\s*\d+)?\)$/s);
  if(byteMatch){ const s=evalExprWithEnv(byteMatch[1],env); const i=parseInt(byteMatch[2]); if(typeof s==='string'&&i>=1&&i<=s.length) return s.charCodeAt(i-1); }
  const tcMatch=expr.match(/^table\.concat\((\w+)(?:,\s*(.+?))?\)$/s);
  if(tcMatch&&env){
    const tbl=env.get(tcMatch[1]);
    if(tbl&&tbl.type==='table'&&Array.isArray(tbl.value)){
      const sep=tcMatch[2]?(evalExprWithEnv(tcMatch[2],env)??''):'';
      if(typeof sep==='string'){
        const parts=tbl.value.map(v=>typeof v==='string'?v:typeof v==='number'?String(v):null);
        if(parts.every(p=>p!==null)) return parts.join(sep);
      }
    }
  }
  const gfMatch=expr.match(/^(?:getfenv\(\)|_G)\s*\[\s*(.+?)\s*\]$/s);
  if(gfMatch){ const key=evalExprWithEnv(gfMatch[1],env); if(typeof key==='string') return key; }
  const rawgetMatch=expr.match(/^rawget\s*\(\s*(?:_G|getfenv\(\))\s*,\s*(.+?)\s*\)$/s);
  if(rawgetMatch){ const key=evalExprWithEnv(rawgetMatch[1],env); if(typeof key==='string') return key; }
  const concatParts=splitByConcat(expr);
  if(concatParts.length>1){
    const resolved=concatParts.map(p=>evalExprWithEnv(p.trim(),env));
    if(resolved.every(v=>v!==null)) return resolved.map(String).join('');
  }
  if(env&&/^\w+$/.test(expr)){ const entry=env.get(expr); if(entry&&(entry.type==='num'||entry.type==='str')) return entry.value; }
  const arrMatch=expr.match(/^(\w+)\[(.+)\]$/);
  if(arrMatch&&env){
    const tbl=env.get(arrMatch[1]);
    if(tbl&&tbl.type==='table'&&Array.isArray(tbl.value)){
      const idx=evalExprWithEnv(arrMatch[2],env);
      if(typeof idx==='number'){ const v=tbl.value[Math.round(idx)-1]; if(v!==undefined) return v; }
    }
  }
  const numResult=evalArithWithEnv(expr,env); if(numResult!==null) return numResult;
  return null;
}

// ════════════════════════════════════════════════════════════════════════
//  #1  autoDeobfuscate 処理順は後述 — まず全パスを実装
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
//  #2  evaluateExpressions  — Lua定数式を正規表現で検出して評価
// ────────────────────────────────────────────────────────────────────────
function deobfuscateSplitStrings(code) {
  let modified = code, found = false, iterations = 0;
  const re1 = /"((?:[^"\\]|\\.)*)"\s*\.\.\s*"((?:[^"\\]|\\.)*)"/g;
  const re2 = /'((?:[^'\\]|\\.)*)'\s*\.\.\s*'((?:[^'\\]|\\.)*)'/g;
  while (re1.test(modified) && iterations < 60) {
    modified = modified.replace(/"((?:[^"\\]|\\.)*)"\s*\.\.\s*"((?:[^"\\]|\\.)*)"/g, (_, a, b) => `"${a}${b}"`);
    found = true; iterations++; re1.lastIndex = 0;
  }
  while (re2.test(modified) && iterations < 120) {
    modified = modified.replace(/'((?:[^'\\]|\\.)*)'\s*\.\.\s*'((?:[^'\\]|\\.)*)'/g, (_, a, b) => `'${a}${b}'`);
    found = true; iterations++; re2.lastIndex = 0;
  }
  if (!found) return { success: false, error: 'SplitStringsパターンが見つかりません', method: 'split_strings' };
  return { success: true, result: modified, method: 'split_strings' };
}

// ────────────────────────────────────────────────────────────────────────
//  #4  charDecoder  — string.char(n,n,...) を文字列へ復元
// ────────────────────────────────────────────────────────────────────────
function charDecoder(code, env) {
  env=env||new SymbolicEnv();
  let modified=code, found=false;
  // まず定数式を畳み込む
  modified=modified.replace(/string\.char\(([^)]+)\)/g,(match,argsStr)=>{
    const val=evalStringChar(argsStr,env); if(val===null) return match;
    const esc=val.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n').replace(/\r/g,'\\r').replace(/\0/g,'\\0');
    found=true; return `"${esc}"`;
  });
  if(!found) return { success:false, error:'string.charパターンが見つかりません', method:'char_decoder' };
  return { success:true, result:modified, method:'char_decoder' };
}

// ────────────────────────────────────────────────────────────────────────
//  #5  xorDecoder  — string.char(x^y) や bit.bxor(x,y) パターンのXOR復号
// ────────────────────────────────────────────────────────────────────────
function xorDecoder(code) {
  let modified=code, found=false;

  // string.char(a ~ b) — Lua5.3以降の ~ 演算子
  modified=modified.replace(/string\.char\((\d+)\s*~\s*(\d+)\)/g,(_,a,b)=>{
    const v=parseInt(a)^parseInt(b); found=true;
    return `string.char(${v})`;
  });

  // bit.bxor(a, b) パターン
  modified=modified.replace(/bit\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g,(_,a,b)=>{
    found=true; return String(parseInt(a)^parseInt(b));
  });

  // string.char(x ^ y) — Lua5.3 XOR
  modified=modified.replace(/\b(\d+)\s*\^\s*(\d+)\b/g,(match,a,b)=>{
    // ^ がべき乗ではなくXORとして使われているかを判断
    // 両方255以下なら XOR として扱う（べき乗なら結果が大きすぎる）
    const ia=parseInt(a),ib=parseInt(b);
    if(ia<=255&&ib<=255){ found=true; return String(ia^ib); }
    return match;
  });

  // XOR配列ブルートフォース (既存コード)
  const xorRes=deobfuscateXOR(code);
  if(xorRes.success) return { ...xorRes, method:'xor_decoder' };

  if(!found) return { success:false, error:'XORパターンが見つかりません', method:'xor_decoder' };
  return { success:true, result:modified, method:'xor_decoder' };
}

// XOR配列ブルートフォース（後方互換）
function deobfuscateXOR(code) {
  function xorByte(b,k){ let r=0; for(let i=0;i<8;i++){const a=(b>>i)&1,bk=(k>>i)&1; if(a!==bk)r|=(1<<i);} return r; }
  const patterns=[/local\s+\w+\s*=\s*\{([0-9,\s]+)\}/g,/\{([0-9,\s]+)\}/g];
  let encryptedArrays=[];
  for(const pattern of patterns){
    let match; const p=new RegExp(pattern.source,pattern.flags);
    while((match=p.exec(code))!==null){
      const nums=match[1].split(',').map(n=>parseInt(n.trim())).filter(n=>!isNaN(n));
      if(nums.length>3) encryptedArrays.push(nums);
    }
    if(encryptedArrays.length>0) break;
  }
  if(encryptedArrays.length===0) return { success:false, error:'暗号化配列が見つかりません', method:'xor' };
  let bestResult=null,bestScore=-1,bestKey=-1;
  for(const arr of encryptedArrays){
    for(let key=0;key<=255;key++){
      const str=arr.map(b=>String.fromCharCode(xorByte(b,key))).join('');
      const score=scoreLuaCode(str);
      if(score>bestScore){ bestScore=score; bestResult=str; bestKey=key; }
    }
  }
  if(bestScore<10) return { success:false, error:'有効なLuaコードが見つかりませんでした', method:'xor' };
  return { success:true, result:bestResult, key:bestKey, score:bestScore, method:'xor' };
}

// ────────────────────────────────────────────────────────────────────────
//  #6  constantArrayResolver  — local t={...} の t[i] を直接値へ置換
// ────────────────────────────────────────────────────────────────────────
function staticCharDecoder(code) {
  let modified = code, found = false;
  // #13: string.char(n, n, ...) の連続パターンを静的に文字列化
  modified = modified.replace(/string\.char\(([^)]+)\)/g, (match, argsStr) => {
    const args = argsStr.split(',').map(a => {
      const n = parseInt(a.trim());
      return isNaN(n) ? null : n;
    });
    if (args.some(a => a === null) || args.some(a => a < 0 || a > 255)) return match;
    found = true;
    const str = args.map(n => String.fromCharCode(n)).join('');
    return `"${str.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n').replace(/\r/g,'\\r')}"`;
  });

  // #14: table.concat({string.char(...)}) パターン
  modified = modified.replace(
    /table\.concat\s*\(\s*\{([^}]+)\}\s*(?:,\s*"[^"]*"\s*)?\)/g,
    (match, inner) => {
      // inner の各要素が string.char(n,...) や "str" の場合に結合
      const parts = inner.split(',').map(p => p.trim());
      const strings = parts.map(p => {
        const scm = p.match(/^string\.char\((\d+)\)$/);
        if (scm) return String.fromCharCode(parseInt(scm[1]));
        const strm = p.match(/^"((?:[^"\\]|\\.)*)"$|^'((?:[^'\\]|\\.)*)'$/);
        if (strm) return strm[1] || strm[2];
        return null;
      });
      if (strings.some(s => s === null)) return match;
      found = true;
      const result = strings.join('');
      return `"${result.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`;
    }
  );

  if (!found) return { success: false, error: 'string.char静的パターンなし', method: 'static_char' };
  return { success: true, result: modified, method: 'static_char' };
}

// ────────────────────────────────────────────────────────────────────────
//  #15  xorDecoder 強化版 — bit32.bxor + ~ 演算子サポート
// ────────────────────────────────────────────────────────────────────────
function xorDecoder(code) {
  let modified = code, found = false;

  // bit32.bxor(a, b) — Lua 5.2
  modified = modified.replace(/bit32\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (_, a, b) => {
    found = true; return String(parseInt(a) ^ parseInt(b));
  });
  // bit.bxor(a, b) — LuaJIT
  modified = modified.replace(/bit\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (_, a, b) => {
    found = true; return String(parseInt(a) ^ parseInt(b));
  });
  // #15: ~ XOR演算子 (Lua5.3+) — string.char内のみ安全に展開
  modified = modified.replace(/string\.char\((\d+)\s*~\s*(\d+)\)/g, (_, a, b) => {
    found = true; return `string.char(${parseInt(a) ^ parseInt(b)})`;
  });
  // 255以下の ^ 演算 (XORとして扱う)
  modified = modified.replace(/\b(\d+)\s*\^\s*(\d+)\b/g, (match, a, b) => {
    const ia = parseInt(a), ib = parseInt(b);
    if (ia <= 255 && ib <= 255) { found = true; return String(ia ^ ib); }
    return match;
  });

  // XOR配列ブルートフォース
  function xorByte(b, k) {
    let r = 0;
    for (let i = 0; i < 8; i++) {
      if (((b >> i) & 1) !== ((k >> i) & 1)) r |= (1 << i);
    }
    return r;
  }
  const patterns = [/local\s+\w+\s*=\s*\{([0-9,\s]+)\}/g, /\{([0-9,\s]+)\}/g];
  let encArrays = [];
  for (const pat of patterns) {
    let m; const p = new RegExp(pat.source, pat.flags);
    while ((m = p.exec(code)) !== null) {
      const nums = m[1].split(',').map(n => parseInt(n.trim())).filter(n => !isNaN(n));
      if (nums.length > 3) encArrays.push(nums);
    }
    if (encArrays.length > 0) break;
  }
  if (encArrays.length > 0) {
    let bestResult = null, bestScore = -1, bestKey = -1;
    for (const arr of encArrays) {
      for (let key = 0; key <= 255; key++) {
        const str = arr.map(b => String.fromCharCode(xorByte(b, key))).join('');
        const score = scoreLuaCode(str);
        if (score > bestScore) { bestScore = score; bestResult = str; bestKey = key; }
      }
    }
    if (bestScore > 10)
      return { success: true, result: bestResult, key: bestKey, score: bestScore, method: 'xor_decoder' };
  }

  if (!found) return { success: false, error: 'XORパターンなし', method: 'xor_decoder' };
  return { success: true, result: modified, method: 'xor_decoder' };
}

// ────────────────────────────────────────────────────────────────────────
//  #40-#53  vmDecompiler — VMログから疑似Luaコードを生成
// ────────────────────────────────────────────────────────────────────────
function stringTransformDecoder(code) {
  let modified=code, found=false;
  const env=new SymbolicEnv();
  // string.reverse("...") を直接評価
  modified=modified.replace(/string\.reverse\s*\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*\)/g,(match,strExpr)=>{
    const s=stripLuaString(strExpr); if(s===null) return match;
    found=true;
    const rev=s.split('').reverse().join('');
    return `"${rev.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`;
  });
  // string.sub("...", i, j)
  modified=modified.replace(/string\.sub\s*\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*,\s*(-?\d+)\s*(?:,\s*(-?\d+))?\s*\)/g,(match,strExpr,iStr,jStr)=>{
    const s=stripLuaString(strExpr); if(s===null) return match;
    let i=parseInt(iStr),j=jStr!==undefined?parseInt(jStr):s.length;
    if(i<0) i=Math.max(0,s.length+i+1); if(j<0) j=s.length+j+1;
    found=true;
    const sub=s.slice(i-1,j);
    return `"${sub.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`;
  });
  // string.rep("...", n)
  modified=modified.replace(/string\.rep\s*\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*,\s*(\d+)\s*\)/g,(match,strExpr,nStr)=>{
    const s=stripLuaString(strExpr); const n=parseInt(nStr);
    if(s===null||isNaN(n)) return match;
    found=true;
    return `"${s.repeat(n).replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`;
  });
  if(!found) return { success:false, error:'stringTransformパターンが見つかりません', method:'str_transform' };
  return { success:true, result:modified, method:'str_transform' };
}

// ────────────────────────────────────────────────────────────────────────
//  #17  base64Detector  — Base64文字列を自動デコード
// ────────────────────────────────────────────────────────────────────────
function base64Detector(code, pool) {
  const B64_RE=/[A-Za-z0-9+\/]{32,}={0,2}/g;
  const found=[]; let m;
  while((m=B64_RE.exec(code))!==null){
    const b64=m[0];
    try {
      const decoded=Buffer.from(b64,'base64').toString('utf8');
      // デコード結果がLuaコードっぽければプールに追加
      if(scoreLuaCode(decoded)>20){
        if(pool) pool.add(decoded,'base64_decode');
        found.push({ b64:b64.substring(0,30)+'...', score:scoreLuaCode(decoded).toFixed(1), decoded:decoded.substring(0,60) });
      }
    } catch {}
  }
  if(found.length===0) return { success:false, error:'Base64Luaコードが見つかりません', method:'base64_detect' };
  return { success:true, found, hints:found.map(f=>`score=${f.score}: "${f.decoded}..."`), method:'base64_detect' };
}

// ────────────────────────────────────────────────────────────────────────
//  EncryptStrings  (後方互換 + charDecoder統合)
// ────────────────────────────────────────────────────────────────────────
function deobfuscateEncryptStrings(code) {
  let modified = code, found = false;
  modified = modified.replace(/string\.char\(([\d,\s]+)\)/g, (_, nums) => {
    const chars = nums.split(',').map(n => parseInt(n.trim())).filter(n => !isNaN(n) && n >= 0 && n <= 65535);
    if (chars.length === 0) return _;
    found = true;
    return `"${chars.map(c => { const ch = String.fromCharCode(c); return ch === '"' ? '\\"' : ch === '\\' ? '\\\\' : ch; }).join('')}"`;
  });
  modified = modified.replace(/"((?:\\[0-9]{1,3}|\\x[0-9a-fA-F]{2}|[^"\\])+)"/g, (match, inner) => {
    if (!/\\[0-9]|\\x/i.test(inner)) return match;
    try {
      const decoded = resolveLuaStringEscapes(inner);
      if ([...decoded].every(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126)) {
        found = true;
        return `"${decoded.replace(/"/g, '\\"').replace(/\\/g, '\\\\')}"`;
      }
    } catch {}
    return match;
  });
  if (!found) return { success: false, error: 'EncryptStringsパターンが見つかりません', method: 'encrypt_strings' };
  return { success: true, result: modified, method: 'encrypt_strings' };
}

// ════════════════════════════════════════════════════════════════════════
//  #18 + #19  recursiveDeobfuscate  — 再帰的解析 + seenCodeCache
// ════════════════════════════════════════════════════════════════════════
function decodeEscapedString(str) {
  if (!str) return str;
  // \000〜\255 の数値エスケープ
  let result = str.replace(/\\([0-9]{1,3})/g, (_, n) => {
    const code = parseInt(n, 10);
    return code <= 255 ? String.fromCharCode(code) : _;
  });
  // \xHH 形式
  result = result.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) =>
    String.fromCharCode(parseInt(h, 16))
  );
  // \uHHHH 形式
  result = result.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) =>
    String.fromCharCode(parseInt(h, 16))
  );
  return result;
}

// コード全体の文字列リテラルをデコード
function decodeAllEscapedStrings(code) {
  if (!code) return { result: code, count: 0 };
  let count = 0;
  const result = code.replace(/"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'/g, (match, d, s) => {
    const inner = d !== undefined ? d : s;
    const q     = d !== undefined ? '"' : "'";
    const decoded = inner.replace(/\\([0-9]{1,3})/g, (_, n) => {
      const c = parseInt(n, 10);
      if (c <= 255) { count++; return String.fromCharCode(c); }
      return _;
    });
    if (decoded !== inner) return q + decoded + q;
    return match;
  });
  return { result, count };
}

// ── 項目 8: decodeStringBuilder — string.char + table.concat 復号 ──────
function decodeStringBuilder(code) {
  if (!code) return { result: code, found: false, decoded: [] };
  let modified = code;
  const decoded = [];

  // パターン1: table.concat({string.char(n,n,...), string.char(...),...})
  modified = modified.replace(
    /table\.concat\s*\(\s*\{((?:\s*string\.char\s*\([^)]+\)\s*,?\s*)+)\}\s*(?:,\s*(?:"[^"]*"|'[^']*'))?\s*\)/g,
    (match, inner) => {
      const chars = [];
      const scRe  = /string\.char\s*\(([^)]+)\)/g;
      let sm;
      while ((sm = scRe.exec(inner)) !== null) {
        for (const n of sm[1].split(',')) {
          const c = parseInt(n.trim());
          if (!isNaN(c) && c >= 0 && c <= 255) chars.push(c);
          else return match;  // 非定数ならスキップ
        }
      }
      if (chars.length === 0) return match;
      const str = chars.map(c => String.fromCharCode(c)).join('');
      decoded.push({ pattern: 'table.concat+string.char', value: str });
      const safe = str.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n').replace(/\0/g,'\\0');
      return `"${safe}"`;
    }
  );

  // パターン2: string.char(n,n,...) の直接リスト (長いもの優先)
  modified = modified.replace(/string\.char\(([^)]+)\)/g, (match, args) => {
    const nums = args.split(',').map(a => {
      const t = a.trim();
      // 算術式 (XOR など) も簡易評価
      try { const v = Function('"use strict";return(' + t + ')')(); return typeof v==='number' ? Math.round(v) : null; }
      catch { return null; }
    });
    if (nums.some(n => n === null || n < 0 || n > 255)) return match;
    const str = nums.map(n => String.fromCharCode(n)).join('');
    decoded.push({ pattern: 'string.char', value: str });
    const safe = str.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n').replace(/\0/g,'\\0');
    return `"${safe}"`;
  });

  // パターン3: ("str1") .. ("str2") .. ... の連結を結合
  modified = modified.replace(/"((?:[^"\\]|\\.)*)"\s*\.\.\s*"((?:[^"\\]|\\.)*)"/g,
    (_, a, b) => { decoded.push({ pattern: 'concat', value: a + b }); return `"${a}${b}"`; }
  );
  // 繰り返し適用 (最大5回)
  for (let i = 0; i < 5; i++) {
    const prev = modified;
    modified = modified.replace(/"((?:[^"\\]|\\.)*)"\s*\.\.\s*"((?:[^"\\]|\\.)*)"/g,
      (_, a, b) => `"${a}${b}"`
    );
    if (modified === prev) break;
  }

  return { result: modified, found: decoded.length > 0, decoded };
}

// ── 項目 4: vmhookログから opcodeMap を生成 ──────────────────────────────
// vmTrace (parseVmTrace の entries) を受け取り、Weredev固有の
// opcode番号→名前マッピングを構築する

module.exports = {
  CapturePool, SymbolicEnv,
  evalLuaNumExpr, evalSimpleExpr, evalStringChar, evalArithWithEnv, evalExprWithEnv,
  deobfuscateSplitStrings, charDecoder, xorDecoder, deobfuscateXOR,
  staticCharDecoder, stringTransformDecoder, base64Detector, deobfuscateEncryptStrings,
  decodeEscapedString, decodeAllEscapedStrings, decodeStringBuilder,
};
