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
//  純粋なBase64文字列のみに適用（デコード結果が有効なUTF-8かつ可視率60%以上）
// ────────────────────────────────────────────────────────────────────────
function tryBase64Decode(str) {
  const s = str.trim();
  // Base64文字列として妥当な形式か判定
  if (!/^[A-Za-z0-9+/]{4,}={0,2}$/.test(s)) return null;
  // 長さが4の倍数かチェック
  if (s.replace(/=/g, '').length % 4 === 1) return null;
  try {
    const decoded = Buffer.from(s, 'base64').toString('utf8');
    // デコード結果に置換文字(U+FFFD)が含まれていたら無効
    if (decoded.includes('\uFFFD')) return null;
    // 可視文字率が60%以上なら有効とみなす
    if (visibilityRate(decoded) >= 0.6) return decoded;
    return null;
  } catch {
    return null;
  }
}

// ────────────────────────────────────────────────────────────────────────
//  Step 3: 可視率判定付き総当たりXORデコード (key: 0x00〜0xFF)
//  可視文字率が閾値(0.85)を超えた最初のkeyで復号し返す
// ────────────────────────────────────────────────────────────────────────
function tryXorDecode(str) {
  // XOR対象として妥当な長さか（短すぎると誤検知が多い）
  if (str.length < 4) return null;

  let bestKey    = -1;
  let bestResult = null;
  let bestRate   = 0;

  for (let key = 1; key <= 0xFF; key++) {
    const decoded = xorString(str, key);
    const rate    = visibilityRate(decoded);
    if (rate > bestRate) {
      bestRate   = rate;
      bestResult = decoded;
      bestKey    = key;
    }
    // 可視率85%以上なら即採用
    if (rate >= 0.85) break;
  }

  // 可視率が70%未満なら元の文字列を返さない（ノイズ防止）
  if (bestRate < 0.70) return null;
  return bestResult;
}

// XOR復号ヘルパー
function xorString(str, key) {
  let result = '';
  for (let i = 0; i < str.length; i++) {
    result += String.fromCharCode(str.charCodeAt(i) ^ key);
  }
  return result;
}

// 可視文字率計算（0x20〜0x7E + 一般的な制御文字を可視とみなす）
function visibilityRate(str) {
  if (!str || str.length === 0) return 0;
  let visible = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if ((c >= 0x20 && c <= 0x7E) || c === 0x09 || c === 0x0A || c === 0x0D) {
      visible++;
    }
  }
  return visible / str.length;
}

// ────────────────────────────────────────────────────────────────────────
//  weredevsCustomB64Decode — Vテーブルを使った独自Base64デコード
//  Vテーブルのマッピングをコードから動的に抽出してデコードする
// ────────────────────────────────────────────────────────────────────────
function buildVTable(sourceCode) {
  // Vテーブルが定義されているブロックを抽出
  const vmatch = sourceCode.match(/local\s+(?:V|g)\s*=\s*\{([\s\S]{100,}?)\}(?:local\s+\w+\s*=\s*string\.sub|for\s+\w)/);
  if (!vmatch) return null;
  const vtext = vmatch[1];
  const vtable = {};

  // パターン1: ["\048"]= 形式（数値エスケープ）
  const re1 = /\[\"\\?(\d+)\"\]\s*=\s*([\d+\-*(). ]+)/g;
  let m;
  while ((m = re1.exec(vtext)) !== null) {
    try {
      const k = String.fromCharCode(parseInt(m[1]));
      const v = Function('return ' + m[2])();
      if (Number.isFinite(v) && v >= 0 && v < 64) vtable[k] = v;
    } catch (_) {}
  }

  // パターン2: 単一英字キー  h=11, z=24 など
  const re2 = /(?:^|[,;{])\s*([a-zA-Z])\s*=\s*((?:-?\d+[+\-](?:-\d+|-?\(-?\d+\))|-?\d+)(?:\s*[+\-]\s*(?:-?\d+|-?\(-?\d+\)))*)/g;
  while ((m = re2.exec(vtext)) !== null) {
    try {
      const v = Function('return ' + m[2])();
      if (Number.isFinite(v) && v >= 0 && v < 64) vtable[m[1]] = v;
    } catch (_) {}
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

  // 可視率60%以上なら即採用（制御文字を除去して返す）
  if (rate >= 0.6) {
    return raw.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
  }

  // 可視率が低い場合はXOR層が重なっている可能性があるので試みる
  if (raw.length >= 3) {
    const xorResult = tryXorDecode(raw);
    if (xorResult !== null) return xorResult;
  }

  return null;
}

// ────────────────────────────────────────────────────────────────────────
//  weredevsDecode — Weredevs文字列層の完全デコードパイプライン
//  処理順: 1. Lua escape  →  2. Vテーブル独自Base64  →  3. 標準Base64  →  4. XOR
// ────────────────────────────────────────────────────────────────────────
function weredevsDecode(str, vtable) {
  if (typeof str !== 'string') return str;

  // 1. Lua数値エスケープを展開
  let result = decodeLuaEscapes(str);

  // 2. Vテーブル独自Base64デコード（Weredevs専用）
  if (vtable) {
    const vResult = weredevsVTableDecode(result, vtable);
    if (vResult !== null) return vResult;
  }

  // 3. 標準Base64デコード
  const b64Result = tryBase64Decode(result);
  if (b64Result !== null) return b64Result;

  // 4. 可視率判定付き総当たりXORデコード
  const xorResult = tryXorDecode(result);
  if (xorResult !== null) return xorResult;

  return result;
}

module.exports = {
  decodeLuaEscapes,
  tryBase64Decode,
  tryXorDecode,
  xorString,
  visibilityRate,
  weredevsDecode,
  buildVTable,
  weredevsVTableDecode,
};
