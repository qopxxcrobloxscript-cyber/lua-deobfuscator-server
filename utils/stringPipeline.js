// utils/stringPipeline.js
'use strict';

// ────────────────────────────────────────────────────────────────────────
//  Step 1: Lua数値エスケープ展開  \072 → "H"
// ────────────────────────────────────────────────────────────────────────
function decodeLuaEscapes(str) {
  return str.replace(/\\(\d{1,3})/g, (_, num) => {
    const code = parseInt(num, 10);
    return code <= 255 ? String.fromCharCode(code) : _;
  });
}

// ────────────────────────────────────────────────────────────────────────
//  Step 2: Base64デコード
// ────────────────────────────────────────────────────────────────────────
function tryBase64Decode(str) {
  const s = str.trim();
  if (!/^[A-Za-z0-9+/]{4,}={0,2}$/.test(s)) return null;
  if (s.replace(/=/g, '').length % 4 === 1) return null;
  try {
    const decoded = Buffer.from(s, 'base64').toString('utf8');
    if (decoded.includes('\uFFFD')) return null;
    if (visibilityRate(decoded) >= 0.6) return decoded;
    return null;
  } catch {
    return null;
  }
}

// ────────────────────────────────────────────────────────────────────────
//  Step 3: XORデコード
// ────────────────────────────────────────────────────────────────────────
function tryXorDecode(str) {
  if (str.length < 4) return null;
  let bestKey = -1, bestResult = null, bestRate = 0;
  for (let key = 1; key <= 0xFF; key++) {
    const decoded = xorString(str, key);
    const rate = visibilityRate(decoded);
    if (rate > bestRate) { bestRate = rate; bestResult = decoded; bestKey = key; }
    if (rate >= 0.85) break;
  }
  if (bestRate < 0.70) return null;
  return bestResult;
}

function xorString(str, key) {
  let result = '';
  for (let i = 0; i < str.length; i++) result += String.fromCharCode(str.charCodeAt(i) ^ key);
  return result;
}

function visibilityRate(str) {
  if (!str || str.length === 0) return 0;
  let visible = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if ((c >= 0x20 && c <= 0x7E) || c === 0x09 || c === 0x0A || c === 0x0D) visible++;
  }
  return visible / str.length;
}

// ════════════════════════════════════════════════════════════════════════
//  Weredevs 独自Base64 デコーダー
//  ─ 今回の解析で判明した正確な実装 ─
//
//  Weredevsは標準Base64ではなく独自のgテーブル（文字→0〜63の値）で
//  エンコードされている。コード内の `local g={...}` がそのマッピング。
//
//  デコードアルゴリズム（コードから完全再現）:
//    h=0, a=0
//    各文字 c について:
//      w = g[c] が存在する場合:
//        h += w * 64^(3-a)
//        a++
//        a==4 になったら:
//          b1=floor(h/65536), b2=floor((h%65536)/256), b3=h%256
//          output chr(b1)+chr(b2)+chr(b3), h=0, a=0
//      c=='=' の場合:
//        output chr(floor(h/65536))
//        次が'='でなければ output chr(floor((h%65536)/256))
//        break
// ════════════════════════════════════════════════════════════════════════

/**
 * コードソースから Weredevs の gテーブルマッピングを動的に抽出する。
 *
 * 対象: `do local E=math.floor local W=F local g={...} ...` ブロック内の
 *        `local g={e=..., Y=..., ["\\056"]=..., ...}` テーブル。
 *
 * @param {string} sourceCode  難読化されたLuaコード全体
 * @returns {Object|null}      { char → number(0〜63) } または null
 */
function extractWeredevsGMap(sourceCode) {
  if (!sourceCode || typeof sourceCode !== 'string') return null;

  // gテーブルブロックを抽出
  // "local g={...}local q=string.sub" のパターンを探す
  const gMatch = sourceCode.match(/local\s+g\s*=\s*\{([^}]+)\}local\s+q\s*=\s*string\.sub/s);
  if (!gMatch) return null;

  const gRaw = gMatch[1];
  const gMap = {};

  function evalExpr(expr) {
    if (!expr) return null;
    // "+-" → "-" に正規化
    const normalized = expr.trim().replace(/\+-/g, '-');
    try {
      // 安全な数値演算のみ評価
      if (!/^[\d\s+\-*().]+$/.test(normalized)) return null;
      const result = Function('"use strict"; return (' + normalized + ')')();
      if (typeof result === 'number' && isFinite(result)) return Math.floor(result);
    } catch {}
    return null;
  }

  // パターン1: 英字1文字キー  e=900270-900248
  const letterRe = /(?<!["\w.])([A-Za-z])\s*=\s*([-\d+*(). ]+?)(?=[,;\n}]|[A-Za-z]+=|\[)/g;
  let m;
  while ((m = letterRe.exec(gRaw)) !== null) {
    const v = evalExpr(m[2]);
    if (v !== null && v >= 0 && v <= 63) gMap[m[1]] = v;
  }

  // パターン2: エスケープ数値キー  ["\\056"]=662788+-662776
  const escRe = /\["\\+(\d{1,3})"\]\s*=\s*([-\d+*(). ]+?)(?=[,;\n}]|[A-Za-z]+=|\[)/g;
  while ((m = escRe.exec(gRaw)) !== null) {
    const c = String.fromCharCode(parseInt(m[1], 10));
    const v = evalExpr(m[2]);
    if (v !== null && v >= 0 && v <= 63) gMap[c] = v;
  }

  return Object.keys(gMap).length >= 30 ? gMap : null;
}

/**
 * Weredevs 独自Base64 1文字列をデコードする。
 *
 * @param {string} encoded  gテーブルでエンコードされた文字列
 * @param {Object} gMap     extractWeredevsGMap() の返り値
 * @returns {string}        デコード済み文字列
 */
function weredevsCustomDecode(encoded, gMap) {
  if (!encoded || !gMap) return encoded || '';
  let h = 0, a = 0;
  const result = [];

  for (let i = 0; i < encoded.length; i++) {
    const c = encoded[i];
    const w = gMap[c];
    if (w !== undefined) {
      h += w * Math.pow(64, 3 - a);
      a++;
      if (a === 4) {
        a = 0;
        const b1 = Math.floor(h / 65536);
        const b2 = Math.floor((h % 65536) / 256);
        const b3 = h % 256;
        if (b1) result.push(String.fromCharCode(b1));
        if (b2) result.push(String.fromCharCode(b2));
        if (b3) result.push(String.fromCharCode(b3));
        h = 0;
      }
    } else if (c === '=') {
      const b1 = Math.floor(h / 65536);
      if (b1) result.push(String.fromCharCode(b1));
      if (i < encoded.length - 1 && encoded[i + 1] !== '=') {
        const b2 = Math.floor((h % 65536) / 256);
        if (b2) result.push(String.fromCharCode(b2));
      }
      break;
    }
    // gマップにない文字（ゴミ文字）はスキップ
  }
  return result.join('');
}

/**
 * F[]テーブルのシャッフル処理を逆算して元の順序に戻す。
 *
 * Weredevsは `for E,W in ipairs({{lo1,hi1},{lo2,hi2},...})` で
 * F[]の範囲をリバースするシャッフルを行う。
 * この関数はそのシャッフル指定を解析し、配列を元に戻す。
 *
 * @param {string[]} arr          F[]の生要素配列（0-indexed）
 * @param {string}   sourceCode   難読化コード（シャッフル仕様を抽出するため）
 * @returns {string[]}            シャッフル前の元配列
 */
function unshuffleFArray(arr, sourceCode) {
  // for E,W in ipairs({{...},{...},...}) の部分を抽出
  const swapMatch = sourceCode.match(
    /for\s+E\s*,\s*W\s+in\s+ipairs\s*\(\s*\{([\s\S]*?)\}\s*\)\s*do\s*while/
  );
  if (!swapMatch) return arr;

  const swapRaw = swapMatch[1];

  function evalExpr(expr) {
    try {
      const normalized = expr.trim().replace(/\+-/g, '-');
      if (!/^[\d\s+\-*().]+$/.test(normalized)) return null;
      return Math.floor(Function('"use strict"; return (' + normalized + ')')());
    } catch { return null; }
  }

  // 各 {lo, hi} ペアを抽出
  const pairRe = /\{([^}]+)\}/g;
  let m;
  const swaps = [];
  while ((m = pairRe.exec(swapRaw)) !== null) {
    const parts = m[1].split(/[;,]/).map(p => evalExpr(p));
    if (parts.length >= 2 && parts[0] !== null && parts[1] !== null) {
      // 1-indexed → 0-indexed に変換
      swaps.push([parts[0] - 1, parts[1] - 1]);
    }
  }

  // シャッフルを逆順に適用（元に戻す）
  // ※ Weredevsのシャッフルは各ペアで範囲をリバース（自己逆変換）なので
  //   逆順適用 = 同じ操作を逆順で実行
  const result = [...arr];
  for (let si = swaps.length - 1; si >= 0; si--) {
    let [lo, hi] = swaps[si];
    while (lo < hi) {
      [result[lo], result[hi]] = [result[hi], result[lo]];
      lo++; hi--;
    }
  }
  return result;
}

/**
 * Weredevs 難読化コードから F[]定数プールを完全デコードする。
 *
 * パイプライン:
 *   1. F[]の生要素を抽出
 *   2. シャッフル処理を逆算して元の順序に戻す
 *   3. 各要素: Luaエスケープ → Weredevs独自Base64デコード
 *
 * @param {string} sourceCode  難読化されたLuaコード
 * @returns {{
 *   success: boolean,
 *   pool: string[],           // 1-indexed（pool[1]がF[1]に対応）
 *   gMap: Object,
 *   count: number,
 *   method: string
 * }}
 */
function decodeWeredevsFPool(sourceCode) {
  if (!sourceCode || typeof sourceCode !== 'string') {
    return { success: false, error: 'コードが空', pool: [], gMap: {}, count: 0, method: 'weredevs_fpool' };
  }

  // Step 1: F[]テーブルを抽出
  const fMatch = sourceCode.match(/local\s+F\s*=\s*\{([\s\S]*?)\}local\s+function\s+E/);
  if (!fMatch) {
    return { success: false, error: 'F[]テーブルが見つかりません', pool: [], gMap: {}, count: 0, method: 'weredevs_fpool' };
  }

  // 文字列要素を抽出（"..." 形式）
  const rawElements = [];
  const elemRe = /"((?:\\.|[^"\\])*)"/g;
  let em;
  while ((em = elemRe.exec(fMatch[1])) !== null) {
    rawElements.push(em[1]);
  }

  if (rawElements.length === 0) {
    return { success: false, error: 'F[]に要素が見つかりません', pool: [], gMap: {}, count: 0, method: 'weredevs_fpool' };
  }

  // Step 2: シャッフルを逆算
  const unshuffled = unshuffleFArray(rawElements, sourceCode);

  // Step 3: gテーブルマッピングを抽出
  const gMap = extractWeredevsGMap(sourceCode);
  if (!gMap) {
    return { success: false, error: 'gテーブルマッピングが抽出できません', pool: [], gMap: {}, count: 0, method: 'weredevs_fpool' };
  }

  // Step 4: 各要素をデコード（1-indexed poolとして返す）
  const pool = [null]; // pool[0]は未使用、pool[1]がF[1]
  for (const raw of unshuffled) {
    const step1 = decodeLuaEscapes(raw);   // \099\106... → Weredevs独自Base64文字列
    const step2 = weredevsCustomDecode(step1, gMap);  // 独自Base64 → 実際の文字列
    // 印字可能文字のみ残してクリーニング
    const clean = step2.replace(/[^\x20-\x7e\n\t]/g, '');
    pool.push(clean);
  }

  const meaningful = pool.filter((s, i) => i > 0 && s && s.length >= 2);

  return {
    success: true,
    pool,
    gMap,
    count: rawElements.length,
    meaningfulCount: meaningful.length,
    method: 'weredevs_fpool',
  };
}

// ────────────────────────────────────────────────────────────────────────
//  weredevsDecode — 後方互換維持（旧 API）
//  単一文字列のデコード。sourceCode が渡された場合は動的にgMapを抽出。
//  渡されない場合は従来のVテーブル方式にフォールバック。
// ────────────────────────────────────────────────────────────────────────

/**
 * Weredevs文字列層の完全デコードパイプライン（後方互換版）
 *
 * @param {string}      str      デコード対象文字列
 * @param {Object|null} vtable   旧VテーブルまたはgMap（どちらも可）
 * @param {string|null} sourceCode  難読化コード全体（あればgMapを動的抽出）
 */
function weredevsDecode(str, vtable, sourceCode) {
  if (typeof str !== 'string') return str;

  // 1. Lua数値エスケープを展開
  let result = decodeLuaEscapes(str);

  // 2. sourceCodeがあればgMapを動的抽出して独自Base64デコード
  if (sourceCode && typeof sourceCode === 'string') {
    const gMap = extractWeredevsGMap(sourceCode);
    if (gMap) {
      const decoded = weredevsCustomDecode(result, gMap);
      if (decoded && visibilityRate(decoded) >= 0.5) return decoded;
    }
  }

  // 3. vtableがgMap形式（値が0〜63の数値）なら独自Base64デコード
  if (vtable && typeof vtable === 'object') {
    const vals = Object.values(vtable);
    const isGMap = vals.length >= 30 && vals.every(v => typeof v === 'number' && v >= 0 && v <= 63);
    if (isGMap) {
      const decoded = weredevsCustomDecode(result, vtable);
      if (decoded && visibilityRate(decoded) >= 0.5) return decoded;
    }
  }

  // 4. 旧Vテーブル方式（後方互換）
  if (vtable) {
    const vResult = weredevsVTableDecode(result, vtable);
    if (vResult !== null) return vResult;
  }

  // 5. 標準Base64デコード
  const b64Result = tryBase64Decode(result);
  if (b64Result !== null) return b64Result;

  // 6. XORデコード
  const xorResult = tryXorDecode(result);
  if (xorResult !== null) return xorResult;

  return result;
}

// ────────────────────────────────────────────────────────────────────────
//  旧 weredevsVTableDecode（後方互換維持）
// ────────────────────────────────────────────────────────────────────────
function buildVTable(sourceCode) {
  const vmatch = sourceCode.match(/local\s+(?:V|g)\s*=\s*\{([\s\S]{100,}?)\}(?:local\s+\w+\s*=\s*string\.sub|for\s+\w)/);
  if (!vmatch) return null;
  const vtext = vmatch[1];
  const vtable = {};

  const re1 = /\[\"\\?(\d+)\"\]\s*=\s*([\d+\-*(). ]+)/g;
  let m;
  while ((m = re1.exec(vtext)) !== null) {
    try {
      const k = String.fromCharCode(parseInt(m[1]));
      const v = Function('return ' + m[2])();
      if (Number.isFinite(v) && v >= 0 && v < 64) vtable[k] = v;
    } catch {}
  }

  const re2 = /(?:^|[,;{])\s*([a-zA-Z])\s*=\s*((?:-?\d+[+\-](?:-\d+|-?\(-?\d+\))|-?\d+)(?:\s*[+\-]\s*(?:-?\d+|-?\(-?\d+\)))*)/g;
  while ((m = re2.exec(vtext)) !== null) {
    try {
      const v = Function('return ' + m[2])();
      if (Number.isFinite(v) && v >= 0 && v < 64) vtable[m[1]] = v;
    } catch {}
  }

  return Object.keys(vtable).length >= 32 ? vtable : null;
}

function weredevsVTableDecode(str, vtable) {
  if (!vtable || !str) return null;
  let D = 0, j = 0;
  const g = [];
  for (let q = 0; q < str.length; q++) {
    const ch = str[q];
    const mv = vtable[ch];
    if (mv !== undefined) {
      D = D + mv * Math.pow(64, 3 - j);
      j++;
      if (j === 4) {
        j = 0;
        g.push(String.fromCharCode(Math.floor(D / 65536), Math.floor((D % 65536) / 256), D % 256));
        D = 0;
      }
    } else if (ch === '=') {
      g.push(String.fromCharCode(Math.floor(D / 65536)));
      if (q < str.length - 1 && str[q + 1] !== '=') {
        g.push(String.fromCharCode(Math.floor((D % 65536) / 256)));
      }
      break;
    }
  }
  const raw = g.join('').replace(/\x00+$/g, '');
  const rate = visibilityRate(raw);
  if (rate >= 0.6) return raw.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
  if (raw.length >= 3) {
    const xorResult = tryXorDecode(raw);
    if (xorResult !== null) return xorResult;
  }
  return null;
}

module.exports = {
  decodeLuaEscapes,
  tryBase64Decode,
  tryXorDecode,
  xorString,
  visibilityRate,
  // 新API（今回追加）
  extractWeredevsGMap,
  weredevsCustomDecode,
  unshuffleFArray,
  decodeWeredevsFPool,
  // 旧API（後方互換維持）
  weredevsDecode,
  buildVTable,
  weredevsVTableDecode,
};
