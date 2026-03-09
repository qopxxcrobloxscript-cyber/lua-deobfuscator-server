// utils/luaPrinter.js
'use strict';

const _seenCodeCache = new Map(); // hash -> result
function cacheHash(code) {
  return require('crypto').createHash('sha1').update(code).digest('hex');
}
function cacheGet(code) { return _seenCodeCache.get(cacheHash(code)) || null; }
function cacheSet(code, result) {
  const h = cacheHash(code);
  if (_seenCodeCache.size > 500) {
    // LRU簡易: 古いエントリを半分削除
    const keys = [..._seenCodeCache.keys()].slice(0, 250);
    keys.forEach(k => _seenCodeCache.delete(k));
  }
  _seenCodeCache.set(h, result);
}

// ────────────────────────────────────────────────────────────────────────
//  #20  capturePool  — 解析途中の文字列・コードを蓄積して再利用
// ────────────────────────────────────────────────────────────────────────
function scoreLuaCode(code) {
  const keywords = ['local','function','end','if','then','else','return','for','do','while','and','or','not','nil','true','false','print','table','string','math'];
  let score = 0;
  keywords.forEach(kw => {
    const m = code.match(new RegExp('\\b' + kw + '\\b', 'g'));
    if (m) score += m.length * 10;
  });
  let printable = 0;
  for (let i = 0; i < Math.min(code.length, 2000); i++) {
    const c = code.charCodeAt(i);
    if (c >= 32 && c <= 126) printable++;
  }
  score += (printable / Math.min(code.length, 2000)) * 100;
  return score;
}
function hashCode(str) {
  let h = 0;
  for (let i = 0; i < Math.min(str.length, 4096); i++)
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  return h.toString(16);
}
function parseLuaArrayElements(content) {
  const elements = [];
  let cur = '', depth = 0, inStr = false, strChar = '', i = 0;
  while (i < content.length) {
    const c = content[i];
    if (!inStr) {
      if (c === '"' || c === "'") { inStr = true; strChar = c; cur += c; }
      else if (c === '[' && content[i+1] === '[') {
        let end = content.indexOf(']]', i + 2);
        if (end === -1) end = content.length - 2;
        cur += content.substring(i, end + 2); i = end + 2; continue;
      }
      else if (c === '{') { depth++; cur += c; }
      else if (c === '}') { depth--; cur += c; }
      else if (c === ',' && depth === 0) { elements.push(cur.trim()); cur = ''; }
      else { cur += c; }
    } else {
      if (c === '\\') { cur += c + (content[i+1] || ''); i += 2; continue; }
      if (c === strChar) inStr = false;
      cur += c;
    }
    i++;
  }
  if (cur.trim()) elements.push(cur.trim());
  return elements;
}
function resolveLuaStringEscapes(str) {
  return str
    .replace(/\\n/g,'\n').replace(/\\t/g,'\t').replace(/\\r/g,'\r')
    .replace(/\\\\/g,'\\').replace(/\\"/g,'"').replace(/\\'/g,"'")
    .replace(/\\x([0-9a-fA-F]{2})/g,(_,h)=>String.fromCharCode(parseInt(h,16)))
    .replace(/\\(\d{1,3})/g,(_,d)=>String.fromCharCode(parseInt(d,10)));
}
function stripLuaString(tok) {
  tok = (tok||'').trim();
  if ((tok.startsWith('"')&&tok.endsWith('"'))||(tok.startsWith("'")&&tok.endsWith("'"))) {
    try { return resolveLuaStringEscapes(tok.slice(1,-1)); } catch { return null; }
  }
  if (tok.startsWith('[[')&&tok.endsWith(']]')) return tok.slice(2,-2);
  return null;
}
function splitByComma(src) {
  const parts=[]; let cur='',depth=0,inStr=false,strCh='';
  for (let i=0;i<src.length;i++) {
    const c=src[i];
    if (!inStr) {
      if (c==='"'||c==="'") { inStr=true; strCh=c; cur+=c; }
      else if (c==='('||c==='{'||c==='[') { depth++; cur+=c; }
      else if (c===')'||c==='}'||c===']') { depth--; cur+=c; }
      else if (c===','&&depth===0) { parts.push(cur.trim()); cur=''; }
      else cur+=c;
    } else {
      if (c==='\\') { cur+=c+(src[i+1]||''); i++; continue; }
      if (c===strCh) inStr=false;
      cur+=c;
    }
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}
function splitByConcat(src) {
  const parts=[]; let cur='',depth=0,inStr=false,strCh=''; let i=0;
  while (i<src.length) {
    const c=src[i];
    if (!inStr) {
      if (c==='"'||c==="'") { inStr=true; strCh=c; cur+=c; i++; continue; }
      if (c==='['&&src[i+1]==='[') {
        let end=src.indexOf(']]',i+2); if (end===-1) end=src.length-2;
        cur+=src.slice(i,end+2); i=end+2; continue;
      }
      if (c==='('||c==='{'||c==='[') { depth++; cur+=c; i++; continue; }
      if (c===')'||c==='}'||c===']') { depth--; cur+=c; i++; continue; }
      if (depth===0&&c==='.'&&src[i+1]==='.') {
        parts.push(cur.trim()); cur=''; i+=2;
        if (src[i]==='.') i++;
        continue;
      }
    } else {
      if (c==='\\') { cur+=c+(src[i+1]||''); i+=2; continue; }
      if (c===strCh) inStr=false;
    }
    cur+=c; i++;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

// ────────────────────────────────────────────────────────────────────────
//  Lua数値式パーサー  (evalLuaNumExpr — v2から引継ぎ)
// ────────────────────────────────────────────────────────────────────────
function stripComments(code) {
  if (!code) return code;
  let result = code;
  // --[[ 長大コメント ]] を削除 (ネスト非対応・実用的な範囲)
  result = result.replace(/--\[=*\[[\s\S]*?\]=*\]/g, '');
  // -- 行コメントを削除 (文字列内は除く: 簡易版)
  result = result.replace(/--[^\[\n][^\n]*/g, '');
  result = result.replace(/--\n/g, '\n');
  // 3行以上の連続空行を1行に
  result = result.replace(/\n{4,}/g, '\n\n');
  return result.trim();
}

// ────────────────────────────────────────────────────────────────────────
//  #3  loaderPatternDetected 強化版 — 複合パターン検出
// ────────────────────────────────────────────────────────────────────────
function beautifyLua(code) {
  if (!code) return code;
  let result = code;
  // 連続した空行を2行以内に
  result = result.replace(/\n{3,}/g, '\n\n');
  // end/else/until の前に空行
  result = result.replace(/([^\n])\n(end|else|elseif|until)\b/g, '$1\n\n$2');
  // function の前に空行
  result = result.replace(/([^\n])\n(local\s+function|function)\b/g, '$1\n\n$2');
  // インデントの正規化 (タブ→2スペース)
  result = result.replace(/\t/g, '  ');
  // 末尾空白削除
  result = result.replace(/[ \t]+$/gm, '');
  return result.trim();
}



// ────────────────────────────────────────────────────────────────────────
//  #16  stringTransformDecoder  — string.reverse/string.sub 型難読化復元
// ────────────────────────────────────────────────────────────────────────

module.exports = {
  cacheHash, cacheGet, cacheSet,
  scoreLuaCode, hashCode,
  parseLuaArrayElements, resolveLuaStringEscapes, stripLuaString,
  splitByComma, splitByConcat, stripComments, beautifyLua,
};
