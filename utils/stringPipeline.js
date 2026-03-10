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
//  weredevsDecode — Weredevs文字列層の完全デコードパイプライン
//  処理順: 1. Lua escape  →  2. Base64  →  3. XOR
// ────────────────────────────────────────────────────────────────────────
function weredevsDecode(str) {
  if (typeof str !== 'string') return str;

  // 1. Lua数値エスケープを展開
  let result = decodeLuaEscapes(str);

  // 2. Base64デコード（展開後の文字列が該当する場合）
  const b64Result = tryBase64Decode(result);
  if (b64Result !== null) {
    result = b64Result;
  }

  // 3. 可視率判定付き総当たりXORデコード
  //    Base64デコードが成功していた場合はXORをスキップ（二重デコード防止）
  if (b64Result === null) {
    const xorResult = tryXorDecode(result);
    if (xorResult !== null) {
      result = xorResult;
    }
  }

  return result;
}

module.exports = {
  decodeLuaEscapes,
  tryBase64Decode,
  tryXorDecode,
  xorString,
  visibilityRate,
  weredevsDecode,
};
