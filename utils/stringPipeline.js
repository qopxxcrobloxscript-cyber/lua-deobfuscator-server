// utils/stringPipeline.js
'use strict';

// ────────────────────────────────────────────────────────────────────────
//  Lua数値エスケープ展開  \072 → "H"
// ────────────────────────────────────────────────────────────────────────
function decodeLuaEscapes(str) {
  return str.replace(/\\(\d{1,3})/g, (_, num) => {
    const code = parseInt(num, 10);
    return code <= 255 ? String.fromCharCode(code) : _;
  });
}

function tryBase64Decode(str) {
  const s = str.trim();
  if (!/^[A-Za-z0-9+/]{4,}={0,2}$/.test(s)) return null;
  if (s.replace(/=/g, '').length % 4 === 1) return null;
  try {
    const decoded = Buffer.from(s, 'base64').toString('utf8');
    if (decoded.includes('\uFFFD')) return null;
    if (visibilityRate(decoded) >= 0.6) return decoded;
    return null;
  } catch { return null; }
}

function tryXorDecode(str) {
  if (str.length < 4) return null;
  let bestResult = null, bestRate = 0;
  for (let key = 1; key <= 0xFF; key++) {
    const decoded = xorString(str, key);
    const rate = visibilityRate(decoded);
    if (rate > bestRate) { bestRate = rate; bestResult = decoded; }
    if (rate >= 0.85) break;
  }
  return bestRate >= 0.70 ? bestResult : null;
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

// ────────────────────────────────────────────────────────────────────────
//  安全な数値演算式評価
// ────────────────────────────────────────────────────────────────────────
function evalNumExpr(expr) {
  if (!expr) return null;
  try {
    const normalized = expr.trim().replace(/\+-/g, '-');
    if (!/^[\d\s+\-*().]+$/.test(normalized)) return null;
    const result = Function('"use strict"; return (' + normalized + ')')();
    if (typeof result === 'number' && isFinite(result)) return Math.floor(result);
  } catch {}
  return null;
}

// ════════════════════════════════════════════════════════════════════════
//  Weredevs 構造動的解析
//
//  Weredevsは難読化のたびにテーブル名・関数名がランダムに変わる。
//  そのため名前ではなく「構造的な特徴」でそれぞれを検出する。
//
//  構造の特徴:
//    [定数プール]   local <名前> = {"\NNN\NNN...", ...}
//                  → 要素が全て数値エスケープ文字列で構成された大きなテーブル
//    [シャッフル]   for <v1>,<v2> in ipairs({{lo,hi},...}) do while ...
//                  → プール要素を範囲リバースでシャッフルする
//    [gマップ]      local <名前>={<文字>=<数値演算>,...} local <q>=string.sub ...
//                  → 直後に string.sub が来る、値が全て 0〜63 のテーブル
//    [アクセサ関数] local function <名前>(<arg>) return <プール>[<arg>-(<式>)] end
//                  → プール名をインデックス補正してアクセスする関数
// ════════════════════════════════════════════════════════════════════════

/**
 * Weredevs難読化コードの構造を動的解析してメタ情報を返す。
 * テーブル名・関数名には依存しない。
 *
 * @param {string} sourceCode
 * @returns {{
 *   poolName:       string|null,
 *   gMapName:       string|null,
 *   accessorName:   string|null,
 *   accessorOffset: number,
 *   shufflePairs:   [number, number][],
 * }}
 */
function detectWeredevsStructure(sourceCode) {
  const result = {
    poolName:       null,
    gMapName:       null,
    accessorName:   null,
    accessorOffset: 0,
    shufflePairs:   [],
  };
  if (!sourceCode || typeof sourceCode !== 'string') return result;

  // ── 定数プールを検出 ──────────────────────────────────────────────
  // 特徴: 要素が全て \NNN\NNN... 形式の数値エスケープ文字列で構成
  //       かつ要素数が多い（Weredevsは通常200〜500要素）
  const poolRe = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{\s*(?:"(?:\\[0-9]{1,3})+"[,;]?\s*){20,}/g;
  let poolM;
  let bestPoolName = null, bestPoolCount = 0;
  while ((poolM = poolRe.exec(sourceCode)) !== null) {
    // 要素数をカウント
    const startIdx = poolM.index + poolM[0].length - poolM[0].match(/\{[^}]*$/)[0].length;
    const snippet  = sourceCode.substring(startIdx, Math.min(sourceCode.length, startIdx + 100));
    const count    = (poolM[0].match(/"(?:\\[0-9]{1,3})+"/g) || []).length;
    if (count > bestPoolCount) {
      bestPoolCount = count;
      bestPoolName  = poolM[1];
    }
  }
  result.poolName = bestPoolName;

  // ── シャッフル仕様を検出 ──────────────────────────────────────────
  // 特徴: for <v1>,<v2> in ipairs({{<数値>,<数値>},...}) do while <v2>[1]<<v2>[2]
  const shuffleRe = /for\s+[A-Za-z_]\w*\s*,\s*[A-Za-z_]\w*\s+in\s+ipairs\s*\(\s*\{([\s\S]*?)\}\s*\)\s*do\s*while/;
  const shuffleM  = shuffleRe.exec(sourceCode);
  if (shuffleM) {
    const pairRe = /\{([^}]+)\}/g;
    let pm;
    while ((pm = pairRe.exec(shuffleM[1])) !== null) {
      const parts = pm[1].split(/[;,]/).map(p => evalNumExpr(p));
      if (parts.length >= 2 && parts[0] !== null && parts[1] !== null) {
        result.shufflePairs.push([parts[0], parts[1]]);
      }
    }
  }

  // ── gマップ（独自Base64マッピング）を検出 ────────────────────────
  // 特徴: local <名前>={...} の直後に local <q>=string.sub が来る
  //       かつテーブルの値が全て 0〜63 に収まる
  const gBlockRe = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{([^}]+)\}\s*local\s+[A-Za-z_]\w*\s*=\s*string\.sub/g;
  let gBlockM;
  while ((gBlockM = gBlockRe.exec(sourceCode)) !== null) {
    const gRaw     = gBlockM[2];
    const gMap     = _parseGMapBody(gRaw);
    const validCnt = Object.values(gMap).filter(v => v >= 0 && v <= 63).length;
    if (validCnt >= 30) {
      result.gMapName = gBlockM[1];
      break;
    }
  }

  // ── アクセサ関数を検出 ────────────────────────────────────────────
  // 特徴: local function <名前>(<arg>) return <プール>[<arg> - (<式>)] end
  const accessorRe = /local\s+function\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*return\s+([A-Za-z_]\w*)\s*\[\s*\2\s*-\s*\(([-\d+*(). ]+)\)\s*\]\s*end/g;
  let accM;
  while ((accM = accessorRe.exec(sourceCode)) !== null) {
    // プール名が一致するか確認
    const fnName   = accM[1];
    const poolRef  = accM[3];
    const offsetEx = accM[4];
    if (result.poolName && poolRef !== result.poolName) continue;
    const offset = evalNumExpr(offsetEx);
    result.accessorName   = fnName;
    result.accessorOffset = offset !== null ? offset : 0;
    break;
  }

  return result;
}

/**
 * gテーブルのbodyから { char → number } マッピングを解析する。
 */
function _parseGMapBody(gRaw) {
  const gMap = {};

  // パターン1: 英字1文字キー  e=900270-900248
  const letterRe = /(?<!["\w.])([A-Za-z])\s*=\s*([-\d+*(). ]+?)(?=[,;\n}]|[A-Za-z]+=|\[)/g;
  let m;
  while ((m = letterRe.exec(gRaw)) !== null) {
    const v = evalNumExpr(m[2]);
    if (v !== null && v >= 0 && v <= 63) gMap[m[1]] = v;
  }

  // パターン2: エスケープ数値キー  ["\\056"]=662788+-662776
  const escRe = /\["\\+(\d{1,3})"\]\s*=\s*([-\d+*(). ]+?)(?=[,;\n}]|[A-Za-z]+=|\[)/g;
  while ((m = escRe.exec(gRaw)) !== null) {
    const c = String.fromCharCode(parseInt(m[1], 10));
    const v = evalNumExpr(m[2]);
    if (v !== null && v >= 0 && v <= 63) gMap[c] = v;
  }

  return gMap;
}

/**
 * コードソースから Weredevs の gテーブルマッピングを動的に抽出する。
 * テーブル名には依存しない。
 *
 * @param {string} sourceCode
 * @returns {Object|null}  { char → number(0〜63) }
 */
function extractWeredevsGMap(sourceCode) {
  if (!sourceCode || typeof sourceCode !== 'string') return null;

  // 「直後に string.sub が来るテーブル」かつ「値が 0〜63」という特徴で検出
  const gBlockRe = /local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{([^}]+)\}\s*local\s+[A-Za-z_]\w*\s*=\s*string\.sub/g;
  let gMatch;
  let bestGMap = null, bestCount = 0;

  while ((gMatch = gBlockRe.exec(sourceCode)) !== null) {
    const gMap     = _parseGMapBody(gMatch[1]);
    const validCnt = Object.values(gMap).filter(v => v >= 0 && v <= 63).length;
    if (validCnt > bestCount) {
      bestCount = validCnt;
      bestGMap  = gMap;
    }
  }

  return bestGMap && bestCount >= 30 ? bestGMap : null;
}

/**
 * F[]のシャッフルを逆算して元の順序に戻す。
 *
 * @param {string[]}           arr     生要素配列（0-indexed）
 * @param {[number,number][]}  pairs   detectWeredevsStructure()のshufflePairs（1-indexed）
 * @returns {string[]}
 */
function unshuffleFArray(arr, pairs) {
  if (!pairs || pairs.length === 0) return arr;
  const result = [...arr];
  // シャッフルは範囲リバース（自己逆変換）→ 逆順適用で元に戻る
  for (let si = pairs.length - 1; si >= 0; si--) {
    let lo = pairs[si][0] - 1; // 1-indexed → 0-indexed
    let hi = pairs[si][1] - 1;
    while (lo < hi) {
      [result[lo], result[hi]] = [result[hi], result[lo]];
      lo++; hi--;
    }
  }
  return result;
}

/**
 * Weredevs 独自Base64デコード（1文字列）。
 *
 * @param {string} encoded
 * @param {Object} gMap    { char → number(0〜63) }
 * @returns {string}
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
  }
  return result.join('');
}

/**
 * Weredevs難読化コードから定数プールを完全デコードする。
 * テーブル名・関数名には一切依存しない。
 *
 * @param {string} sourceCode
 * @returns {{
 *   success:        boolean,
 *   pool:           string[],   // 1-indexed
 *   gMap:           Object,
 *   structure:      Object,
 *   count:          number,
 *   meaningfulCount:number,
 *   method:         string,
 * }}
 */
function decodeWeredevsFPool(sourceCode) {
  if (!sourceCode || typeof sourceCode !== 'string') {
    return { success: false, error: 'コードが空', pool: [], gMap: {}, structure: {}, count: 0, method: 'weredevs_fpool' };
  }

  // Step 1: 構造を動的解析
  const structure = detectWeredevsStructure(sourceCode);

  // Step 2: 定数プールの生要素を抽出
  let rawElements = _extractPoolElements(sourceCode, structure.poolName);

  if (rawElements.length === 0) {
    return { success: false, error: '定数プールが見つかりません', pool: [], gMap: {}, structure, count: 0, method: 'weredevs_fpool' };
  }

  // Step 3: シャッフルを逆算
  const unshuffled = unshuffleFArray(rawElements, structure.shufflePairs);

  // Step 4: gマップを動的抽出
  const gMap = extractWeredevsGMap(sourceCode);
  if (!gMap) {
    return { success: false, error: 'gマップが見つかりません', pool: [], gMap: {}, structure, count: rawElements.length, method: 'weredevs_fpool' };
  }

  // Step 5: 各要素をデコード（1-indexed）
  const pool = [null];
  for (const raw of unshuffled) {
    const step1 = decodeLuaEscapes(raw);
    const step2 = weredevsCustomDecode(step1, gMap);
    pool.push(step2.replace(/[^\x20-\x7e\n\t]/g, ''));
  }

  const meaningful = pool.filter((s, i) => i > 0 && s && s.length >= 2 && /[a-zA-Z]/.test(s));

  return {
    success: true,
    pool,
    gMap,
    structure,
    count: rawElements.length,
    meaningfulCount: meaningful.length,
    method: 'weredevs_fpool',
  };
}

/**
 * 定数プールの生要素（文字列）を抽出する。
 * poolNameが判明している場合はその名前で抽出、
 * 不明な場合は構造（数値エスケープの大きなテーブル）で検出。
 */
function _extractPoolElements(sourceCode, poolName) {
  let rawElements = [];

  // poolNameが判明している場合
  if (poolName) {
    const pEsc   = poolName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // local <poolName> = {...} local function の間を抽出
    const fMatch = sourceCode.match(
      new RegExp(`local\\s+${pEsc}\\s*=\\s*\\{([\\s\\S]*?)\\}\\s*local\\s+function`)
    );
    if (fMatch) {
      const elemRe = /"((?:\\.|[^"\\])*)"/g;
      let em;
      while ((em = elemRe.exec(fMatch[1])) !== null) rawElements.push(em[1]);
    }
  }

  // 見つからない場合: 数値エスケープ文字列だけで構成された大きなテーブルを探す
  if (rawElements.length < 50) {
    // local <名前> = {"\\NNN...", "\\NNN...", ...} で要素が50以上のテーブル
    const bigPoolRe = /local\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{((?:\s*"(?:\\[0-9]{1,3})+"[,;]?\s*){50,})\}/g;
    let bp;
    while ((bp = bigPoolRe.exec(sourceCode)) !== null) {
      const elems  = [];
      const elemRe = /"((?:\\.|[^"\\])*)"/g;
      let em;
      while ((em = elemRe.exec(bp[1])) !== null) elems.push(em[1]);
      if (elems.length > rawElements.length) rawElements = elems;
    }
  }

  return rawElements;
}

// ────────────────────────────────────────────────────────────────────────
//  後方互換 API
// ────────────────────────────────────────────────────────────────────────
function weredevsDecode(str, vtable, sourceCode) {
  if (typeof str !== 'string') return str;
  let result = decodeLuaEscapes(str);

  if (sourceCode && typeof sourceCode === 'string') {
    const gMap = extractWeredevsGMap(sourceCode);
    if (gMap) {
      const decoded = weredevsCustomDecode(result, gMap);
      if (decoded && visibilityRate(decoded) >= 0.5) return decoded;
    }
  }

  if (vtable && typeof vtable === 'object') {
    const vals   = Object.values(vtable);
    const isGMap = vals.length >= 30 && vals.every(v => typeof v === 'number' && v >= 0 && v <= 63);
    if (isGMap) {
      const decoded = weredevsCustomDecode(result, vtable);
      if (decoded && visibilityRate(decoded) >= 0.5) return decoded;
    }
  }

  if (vtable) {
    const vResult = weredevsVTableDecode(result, vtable);
    if (vResult !== null) return vResult;
  }

  const b64Result = tryBase64Decode(result);
  if (b64Result !== null) return b64Result;

  const xorResult = tryXorDecode(result);
  if (xorResult !== null) return xorResult;

  return result;
}

function buildVTable(sourceCode) {
  const gMap = extractWeredevsGMap(sourceCode);
  if (gMap && Object.keys(gMap).length >= 30) return gMap;

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
  const raw  = g.join('').replace(/\x00+$/g, '');
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
  evalNumExpr,
  // Weredevs 動的解析（新API）
  detectWeredevsStructure,
  extractWeredevsGMap,
  weredevsCustomDecode,
  unshuffleFArray,
  decodeWeredevsFPool,
  // 後方互換
  weredevsDecode,
  buildVTable,
  weredevsVTableDecode,
};
