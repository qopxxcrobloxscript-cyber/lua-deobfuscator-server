// utils/luaPrinter.js
'use strict';

const _seenCodeCache = new Map();
function cacheHash(code) {
  return require('crypto').createHash('sha1').update(code).digest('hex');
}
function cacheGet(code) { return _seenCodeCache.get(cacheHash(code)) || null; }
function cacheSet(code, result) {
  const h = cacheHash(code);
  if (_seenCodeCache.size > 500) {
    const keys = [..._seenCodeCache.keys()].slice(0, 250);
    keys.forEach(k => _seenCodeCache.delete(k));
  }
  _seenCodeCache.set(h, result);
}

function scoreLuaCode(code) {
  const keywords = ['local','function','end','if','then','else','return','for','do','while',
                    'and','or','not','nil','true','false','print','table','string','math'];
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
      else cur += c;
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

function stripComments(code) {
  if (!code) return code;
  let result = code;
  result = result.replace(/--\[=*\[[\s\S]*?\]=*\]/g, '');
  result = result.replace(/--[^\[\n][^\n]*/g, '');
  result = result.replace(/--\n/g, '\n');
  result = result.replace(/\n{4,}/g, '\n\n');
  return result.trim();
}

function beautifyLua(code) {
  if (!code) return code;
  let result = code;
  result = result.replace(/\n{3,}/g, '\n\n');
  result = result.replace(/([^\n])\n(end|else|elseif|until)\b/g, '$1\n\n$2');
  result = result.replace(/([^\n])\n(local\s+function|function)\b/g, '$1\n\n$2');
  result = result.replace(/\t/g, '  ');
  result = result.replace(/[ \t]+$/gm, '');
  return result.trim();
}

// ────────────────────────────────────────────────────────────────────────
//  項目10: unwrapVmWrapper — return(function(...)) ラッパーを削除
//
//  対象パターン:
//    return (function(...)
//      -- VM コード
//    end)(...)
//
//  戻り値: { code: string, unwrapped: boolean, wrapperArgs: string[] }
// ────────────────────────────────────────────────────────────────────────
function unwrapVmWrapper(code) {
  if (!code) return { code, unwrapped: false };

  // パターン1: return (function(...) ... end)(...)
  // パターン2: return(function(...) ... end)(...)
  // パターン3: (function(...) ... end)(...)  ← 直接実行
  const wrapperPatterns = [
    /^\s*return\s*\(\s*function\s*\(([^)]*)\)([\s\S]*?)end\s*\)\s*\(([^)]*)\)\s*$/,
    /^\s*\(\s*function\s*\(([^)]*)\)([\s\S]*?)end\s*\)\s*\(([^)]*)\)\s*$/,
  ];

  for (const pat of wrapperPatterns) {
    const m = code.match(pat);
    if (m) {
      const params     = m[1].trim();
      const body       = m[2];
      const callArgs   = m[3].trim();
      // ラッパー本体のコードを取り出す
      const unwrapped  = body.trim();
      if (unwrapped.length > 10) {
        return {
          code:        unwrapped,
          unwrapped:   true,
          wrapperArgs: callArgs ? callArgs.split(',').map(s => s.trim()) : [],
          wrapperParams: params ? params.split(',').map(s => s.trim()) : [],
        };
      }
    }
  }

  // パターン4: 複数行にわたる場合 — 先頭の return(function でネスト解析
  const returnFuncRe = /\breturn\s*\(\s*function\s*\(/;
  const startM = returnFuncRe.exec(code);
  if (startM) {
    // function キーワードの位置から end を探す
    const funcStart = startM.index;
    let depth = 0, endPos = -1;
    const keywords = /\b(function|do|repeat|if|while|for)\b|\bend\b/g;
    keywords.lastIndex = funcStart;
    let km;
    while ((km = keywords.exec(code)) !== null) {
      if (/^(function|do|repeat|if|while|for)$/.test(km[0])) depth++;
      else if (km[0] === 'end') {
        depth--;
        if (depth === 0) { endPos = km.index + 3; break; }
      }
    }
    if (endPos !== -1) {
      // end の後の )(args) を探す
      const suffix = code.substring(endPos).match(/^\s*\)\s*\(([^)]*)\)/);
      if (suffix) {
        const paramM = code.substring(funcStart).match(/function\s*\(([^)]*)\)/);
        const params = paramM ? paramM[1].trim() : '';
        // funcStart の直後の function( から最初の ) まで
        const bodyStart = code.indexOf(')', funcStart + code.substring(funcStart).indexOf('function')) + 1;
        const body = code.substring(bodyStart, endPos - 3).trim();
        if (body.length > 10) {
          return {
            code:          body,
            unwrapped:     true,
            wrapperArgs:   suffix[1] ? suffix[1].split(',').map(s => s.trim()) : [],
            wrapperParams: params ? params.split(',').map(s => s.trim()) : [],
          };
        }
      }
    }
  }

  return { code, unwrapped: false };
}

// ────────────────────────────────────────────────────────────────────────
//  項目12: removeConstDecodeLoop — VM解除後に残る Base64風デコードループを削除
//
//  検出パターン:
//    1. for i=1,#CONST_TABLE do ... BASE64_CHARS ... end
//    2. local VAR = {} for ..., VAR[i] = string.sub(...) end
//    3. string.gsub / string.byte を使った文字変換ループ
//    4. math.floor / bit.bxor を使った数値変換ループ
//
//  戻り値: { code: string, removed: number, patterns: string[] }
// ────────────────────────────────────────────────────────────────────────
function removeConstDecodeLoop(code) {
  if (!code) return { code, removed: 0, patterns: [] };

  let result  = code;
  let removed = 0;
  const patterns = [];

  // パターン1: Base64文字テーブル定義
  //   local BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  const b64TableRe = /local\s+\w+\s*=\s*"[A-Za-z0-9+\/=]{60,}"[^\n]*/g;
  let bm;
  while ((bm = b64TableRe.exec(result)) !== null) {
    result  = result.replace(bm[0], '-- [Base64テーブル定義削除済み]');
    removed++;
    patterns.push('base64_table_literal');
  }

  // パターン2: for ループによる文字デコード
  //   for i = 1, #encoded do ... string.sub / string.byte ... end
  const decodeLoopRe = /for\s+\w+\s*=\s*1\s*,\s*#?\w+\s+do\s*\n[\s\S]{0,400}(?:string\.sub|string\.byte|string\.char|math\.floor|bit\.bxor|bit\.band)[\s\S]{0,400}?\n\s*end/g;
  let dm;
  while ((dm = decodeLoopRe.exec(result)) !== null) {
    // ループが定数デコード目的かチェック（代入先が定数テーブルっぽいか）
    const loopText = dm[0];
    const isDecodeLoop = /string\.byte|string\.sub|bit\.bxor|bit\.band|math\.floor/.test(loopText) &&
                         /\[\s*[ij]\s*\]\s*=/.test(loopText);
    if (isDecodeLoop) {
      result  = result.replace(loopText, '-- [定数デコードループ削除済み]');
      removed++;
      patterns.push('const_decode_for_loop');
    }
  }

  // パターン3: string.gsub によるデコード処理
  //   local DECODED = string.gsub(ENCODED, ".", function(c) ... end)
  const gsubDecodeRe = /local\s+\w+\s*=\s*(?:\(\s*)?string\.gsub\s*\([^)]{0,200}function\s*\([^)]+\)[\s\S]{0,300}?end\s*\)[^\n]*/g;
  let gm;
  while ((gm = gsubDecodeRe.exec(result)) !== null) {
    result  = result.replace(gm[0], '-- [gsub デコード処理削除済み]');
    removed++;
    patterns.push('gsub_decode');
  }

  // パターン4: while ループの Base64/XOR デコードパターン
  //   local i = 1; local out = {}; while i <= #encoded do ... i = i + 1 end
  const whileDecodeRe = /local\s+\w+\s*=\s*\{\}\s*\n[\s\S]{0,100}while\s+\w+\s*<=\s*#\w+\s+do[\s\S]{0,400}?end/g;
  let wm;
  while ((wm = whileDecodeRe.exec(result)) !== null) {
    const wText = wm[0];
    if (/string\.byte|bit\.bxor|bit\.band|math\.floor/.test(wText)) {
      result  = result.replace(wText, '-- [whileデコードループ削除済み]');
      removed++;
      patterns.push('while_decode_loop');
    }
  }

  // 残ったコメント行が連続する場合は整理
  result = result.replace(/(-- \[[^\]]+削除済み\]\n){2,}/g, '-- [複数のデコード処理削除済み]\n');

  return { code: result, removed, patterns };
}

module.exports = {
  cacheHash, cacheGet, cacheSet,
  scoreLuaCode, hashCode,
  parseLuaArrayElements, resolveLuaStringEscapes, stripLuaString,
  splitByComma, splitByConcat, stripComments, beautifyLua,
  unwrapVmWrapper,       // 項目10: return(function(...)) ラッパー除去
  removeConstDecodeLoop, // 項目12: Base64風デコードループ削除
};
