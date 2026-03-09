const express = require('express');
const cors    = require('cors');
const { exec, execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// グローバルエラーハンドラー
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, error: 'コードが大きすぎます（最大10MB）' });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, error: 'サーバー内部エラー' });
});

// temp ディレクトリ
const tempDir = path.join(__dirname, 'temp');
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir);

// ════════════════════════════════════════════════════════
//  Lua / Prometheus 確認
// ════════════════════════════════════════════════════════
function checkLuaAvailable() {
  try { execSync('lua -v 2>&1', { timeout: 3000 }); return 'lua'; } catch {}
  try { execSync('luajit -v 2>&1', { timeout: 3000 }); return 'luajit'; } catch {}
  return null;
}

// Prometheus は Lua5.1 専用なので専用バイナリを探す
function checkLua51Available() {
  try { execSync('lua5.1 -v 2>&1', { timeout: 3000 }); return 'lua5.1'; } catch {}
  try { execSync('luajit -v 2>&1', { timeout: 3000 }); return 'luajit'; } catch {}
  // lua5.4 でも一応試す（動かない場合もある）
  try { execSync('lua -v 2>&1', { timeout: 3000 }); return 'lua'; } catch {}
  return null;
}

function checkPrometheusAvailable() {
  return fs.existsSync(path.join(__dirname, 'prometheus', 'cli.lua'))
      || fs.existsSync(path.join(__dirname, 'cli.lua'));
}

// ════════════════════════════════════════════════════════
//  STATUS  GET /api/status
// ════════════════════════════════════════════════════════
app.get('/api/status', (req, res) => {
  res.json({
    status: 'ok',
    lua: checkLuaAvailable() || 'not installed',
    prometheus: checkPrometheusAvailable() ? 'available' : 'not found',
    deobfuscateMethods: ['auto','advanced_static','eval_expressions','split_strings','xor','constant_array','dynamic','vmify','char_decoder','xor_decoder','math_eval','constant_call','str_transform','dead_branch','junk_clean','vm_detect','vm_extract','base64_detect'],
    obfuscatePresets:   ['Minify', 'Weak', 'Medium', 'Strong'],
    obfuscateSteps:     ['SplitStrings', 'EncryptStrings', 'ConstantArray', 'ProxifyLocals', 'WrapInFunction', 'Vmify'],
  });
});

// ════════════════════════════════════════════════════════
//  解読 API  POST /api/deobfuscate
// ════════════════════════════════════════════════════════
app.post('/api/deobfuscate', async (req, res) => {
  const { code, method } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });

  let result;
  switch (method) {
    case 'xor':             result = xorDecoder(code);                break;
    case 'split_strings':   result = deobfuscateSplitStrings(code);   break;
    case 'encrypt_strings': result = deobfuscateEncryptStrings(code); break;
    case 'constant_array':  result = constantArrayResolver(code);     break;
    case 'eval_expressions':result = evaluateExpressions(code);       break;
    case 'advanced_static': result = advancedStaticDeobfuscate(code); break;
    case 'char_decoder':    result = charDecoder(code);               break;
    case 'xor_decoder':     result = xorDecoder(code);                break;
    case 'math_eval':       result = mathEvaluator(code);             break;
    case 'constant_call':   result = constantCallEvaluator(code);     break;
    case 'str_transform':   result = stringTransformDecoder(code);    break;
    case 'dead_branch':     result = deadBranchRemover(code);         break;
    case 'junk_clean':      result = junkAssignmentCleaner(code);     break;
    case 'vm_detect':       result = { ...vmDetector(code), success: vmDetector(code).isVm }; break;
    case 'vm_extract':      result = vmBytecodeExtractor(code);       break;
    case 'base64_detect':   result = base64Detector(code, new CapturePool()); break;
    case 'vmify':           result = deobfuscateVmify(code);          break;
    case 'dynamic':         result = await tryDynamicExecution(code); break;
    case 'auto':
    default:                result = await autoDeobfuscate(code);    break;
  }

  res.json(result);
});

// 後方互換 (旧エンドポイント)
app.post('/deobfuscate', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(deobfuscateXOR(code));
});

// ════════════════════════════════════════════════════════
//  難読化 API  POST /api/obfuscate  (Prometheus)
// ════════════════════════════════════════════════════════
app.post('/api/obfuscate', async (req, res) => {
  const { code, preset, steps } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(await obfuscateWithPrometheus(code, { preset, steps }));
});

// ════════════════════════════════════════════════════════
//  VM難読化 API  POST /api/vm-obfuscate
// ════════════════════════════════════════════════════════
app.post('/api/vm-obfuscate', async (req, res) => {
  const { code, seed } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(await obfuscateWithCustomVM(code, { seed }));
});


// ════════════════════════════════════════════════════════
//  動的実行  —  Renderサーバー上のLuaを最大限活用
//
//  方針:
//   1. まず動的実行を試みる（これがメイン）
//   2. 動的実行が失敗した場合のみ静的解析にフォールバック
//   3. 多段難読化に対応（動的実行の結果を再帰的に動的実行）
//   4. アンチダンプ・アンチデバッグを無効化してから実行
// ════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════
//  dynamicDecode — #2/#3/#4/#7/#9 統合: loadstring hookedで __DECODED__ dump
// ════════════════════════════════════════════════════════════════════════

/**
 * #7: loaderPatternDetected — table.concat + string.char + loadstring が揃うか
 */
// ════════════════════════════════════════════════════════════════════════
//  BLOCK 1: 前処理 / loaderPattern / safeEnv / hookLoadstring (#1-#18)
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
//  #1  stripComments — 巨大コメント難読化を削除
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
function loaderPatternDetected(code) {
  // パターン1: loadstring + table.concat + string.char
  const p1 = /table\.concat\s*\(/.test(code) &&
              /string\.char\s*\(/.test(code) &&
              /\bloadstring\b|\bload\s*\(/.test(code);
  // パターン2: load + char table (compact style)
  const p2 = /\bload\s*\(\s*\{/.test(code) ||
             (/\bload\s*\(/.test(code) && /\bstring\.char\b/.test(code));
  // パターン3: 巨大 string.char 連結 (50文字以上)
  const p3 = /string\.char\s*\(\s*\d[\d\s,]{40,}\)/.test(code);
  // パターン4: table.concat + number array
  const p4 = /table\.concat\s*\(\s*\{[\s\d,]+\}/.test(code);
  return p1 || p2 || p3 || p4;
}

// ────────────────────────────────────────────────────────────────────────
//  #4/#5  safeEnvPreamble 強化版 — 完全サンドボックス環境
// ────────────────────────────────────────────────────────────────────────
const safeEnvPreamble = `
-- ══ YAJU SafeEnv v4 ══

-- math.random を常に0返しに固定 (ランダム性除去でデコード安定化)
pcall(function()
  math.random = function() return 0 end
  math.randomseed = function() end
end)

-- os.* を固定値/無効化
pcall(function()
  os.exit    = function() end
  os.execute = function() return false, "disabled", -1 end
  os.date    = function() return "2025" end
  os.time    = function() return 1700000000 end
  os.clock   = function() return 0 end
end)

-- bit32 互換レイヤー (未定義環境向け)
if not bit32 then
  bit32 = {
    bnot  = function(x) return -x end,
    band  = function(a,b) local r=0;for i=0,31 do if math.floor(a/2^i)%2==1 and math.floor(b/2^i)%2==1 then r=r+2^i end end;return r end,
    bor   = function(a,b) local r=0;for i=0,31 do if math.floor(a/2^i)%2==1 or math.floor(b/2^i)%2==1 then r=r+2^i end end;return r end,
    bxor  = function(a,b) local r=0;for i=0,31 do if math.floor(a/2^i)%2~=math.floor(b/2^i)%2 then r=r+2^i end end;return r end,
    lshift= function(a,b) return math.floor(a*(2^b))%4294967296 end,
    rshift= function(a,b) return math.floor(a/(2^b)) end,
  }
end

-- io.* 危険関数を無効化
pcall(function()
  io.popen = function() return nil, "disabled" end
end)

-- debug.* を無効化
pcall(function()
  if debug then
    debug.sethook  = function() end
    debug.getinfo  = nil
    debug.getlocal = nil; debug.setlocal   = nil
    debug.getupvalue= nil; debug.setupvalue = nil
    debug.getmetatable = nil; debug.setmetatable = nil
  end
end)

-- require を制限 (ネットワーク/FFI ライブラリを禁止)
local __orig_require = require
pcall(function()
  require = function(m)
    local blocked = {socket=1, ffi=1, jit=1, ["io.popen"]=1}
    if blocked[tostring(m)] then error("require blocked: "..tostring(m)) end
    return __orig_require(m)
  end
end)

-- ──────────────────────────────────────────────────────
-- [1] string.char フック
--   VM bytecode テーブルが string.char(n1,n2,...) で文字列化される
--   パターンを捕捉して __STRCHAR__ マーカーでログ出力する
-- ──────────────────────────────────────────────────────
local __orig_string_char = string.char
local __strchar_log = {}
local __strchar_count = 0
local __strchar_max   = 500   -- 最大500件キャプチャ

string.char = function(...)
  local result = __orig_string_char(...)
  if type(result) == "string" and #result > 3 then
    __strchar_count = __strchar_count + 1
    if __strchar_count <= __strchar_max then
      -- bytecodeらしい長さ (4バイト以上) のみ記録
      __strchar_log[__strchar_count] = result
    end
  end
  return result
end
-- string.char 自体のグローバルも上書き
pcall(function() rawset(_G, "string", string) end)

-- ──────────────────────────────────────────────────────
-- [1] table.concat フック
--   ① デコードステージ出力 (Lua コード復元用)
--   ② VM bytecode テーブル結合のキャプチャ
-- ──────────────────────────────────────────────────────
local __orig_table_concat = table.concat
local __tconcat_log   = {}
local __tconcat_count = 0
local __tconcat_max   = 500

table.concat = function(t, sep, ...)
  local r = __orig_table_concat(t, sep, ...)
  if type(r) == "string" and #r > 10 then
    -- デコードステージ出力
    io.write("\\n__DECODE_STAGE__\\n")
    io.write(r)
    io.write("\\n__DECODE_STAGE_END__\\n")
    io.flush()
    -- VM bytecode 候補として記録 (バイナリっぽい短い結果も含む)
    __tconcat_count = __tconcat_count + 1
    if __tconcat_count <= __tconcat_max then
      __tconcat_log[__tconcat_count] = r
    end
  end
  return r
end

-- pcall フック — エラー文字列を PCALL として出力
local __orig_pcall = pcall
pcall = function(f, ...)
  local ok, r = __orig_pcall(f, ...)
  if type(r) == "string" and #r > 0 then
    io.write("\\n__PCALL__\\n")
    io.write(tostring(r))
    io.write("\\n__PCALL_END__\\n")
    io.flush()
  end
  return ok, r
end

-- 暴走防止: デバッグフックで命令数を制限 (500000命令)
local __safe_ops = 0
local __safe_max = 500000
pcall(function()
  if debug and debug.sethook then
    debug.sethook(function()
      __safe_ops = __safe_ops + 1
      if __safe_ops > __safe_max then
        debug.sethook()
        error("__SAFE_TIMEOUT__", 0)
      end
    end, "", 1000)
  end
end)
-- ══ SafeEnv End ══
`;

// ────────────────────────────────────────────────────────────────────────
//  #6/#7/#8  hookLoadstringCode 強化版 — 全パターンをフック
// ────────────────────────────────────────────────────────────────────────
const hookLoadstringCode = `
-- ══ YAJU hookLoadstring v4 ══
-- [6] __original_loadstring は必ず loadstring or load から取得
local __original_loadstring = loadstring or load
local __decoded_count = 0
local __decoded_best_len = 0

-- [1][2][3][6] loadstring / load 共通フック関数
-- capture条件: #code_str > 10 (短いLuaコードもキャプチャ) [2]
local function __hookLoadstring(code_str, name, mode, env)
  if type(code_str) == "string" and #code_str > 10 then
    __decoded_count = __decoded_count + 1
    -- __DECODED__ マーカーで出力
    io.write("\\n__DECODED_START_" .. tostring(__decoded_count) .. "__\\n")
    io.write(code_str)
    io.write("\\n__DECODED_END_" .. tostring(__decoded_count) .. "__\\n")
    -- LOAD_STAGE としても補助出力
    io.write("\\n__LOAD_STAGE__\\n")
    io.write(code_str)
    io.write("\\n__LOAD_STAGE_END__\\n")
    io.flush()
    if #code_str > __decoded_best_len then
      __decoded_best_len = #code_str
    end
  end
  -- [6] 元の関数に委譲 (__original_loadstring を直接呼ぶ)
  local f, err
  if env ~= nil and __original_loadstring ~= __hookLoadstring then
    f, err = __original_loadstring(code_str, name, mode, env)
  else
    f, err = __original_loadstring(code_str)
  end
  if f then return f end
  return nil, err
end

-- [1][7] _G への代入 + loadstring / load への直接代入を両方行う
-- rawset だけに依存しない
_G.loadstring = __hookLoadstring
_G.load       = __hookLoadstring
loadstring    = __hookLoadstring
load          = __hookLoadstring
if rawset then
  pcall(function() rawset(_G, "loadstring", __hookLoadstring) end)
  pcall(function() rawset(_G, "load",       __hookLoadstring) end)
end
-- ══ hookLoadstring End ══
`;

// ────────────────────────────────────────────────────────────────────────
//  #9/#10  parseDecodedOutputs 強化版 — scoreLuaCodeフィルター付き
// ────────────────────────────────────────────────────────────────────────
function parseDecodedOutputs(stdout) {
  const results = [];

  // __DECODED_START_N__ / __DECODED_END_N__ マーカー
  const re = /__DECODED_START_(\d+)__\n([\s\S]*?)\n__DECODED_END_\1__/g;
  let m;
  while ((m = re.exec(stdout)) !== null) {
    const idx  = parseInt(m[1]);
    const code = m[2];
    if (!code || code.length < 5) continue;
    const score = scoreLuaCode(code);
    if (score > 15) results.push({ idx, code, score });
  }

  // __DECODE_STAGE__ (table.concat フック)
  const reStage = /__DECODE_STAGE__\n([\s\S]*?)\n__DECODE_STAGE_END__/g;
  let idxStage = 1000;
  while ((m = reStage.exec(stdout)) !== null) {
    const code = m[1];
    if (!code || code.length < 5) continue;
    const score = scoreLuaCode(code);
    if (score > 15) results.push({ idx: idxStage++, code, score, source: 'decode_stage' });
  }

  // __LOAD_STAGE__ (load/loadstring 補助フック)
  const reLoad = /__LOAD_STAGE__\n([\s\S]*?)\n__LOAD_STAGE_END__/g;
  let idxLoad = 2000;
  while ((m = reLoad.exec(stdout)) !== null) {
    const code = m[1];
    if (!code || code.length < 5) continue;
    const score = scoreLuaCode(code);
    if (score > 15) results.push({ idx: idxLoad++, code, score, source: 'load_stage' });
  }

  // __PCALL__ (pcall フック — エラー文字列にLuaコードが含まれる場合)
  const rePcall = /__PCALL__\n([\s\S]*?)\n__PCALL_END__/g;
  let idxPcall = 3000;
  while ((m = rePcall.exec(stdout)) !== null) {
    const code = m[1];
    if (!code || code.length < 5) continue;
    const score = scoreLuaCode(code);
    if (score > 15) results.push({ idx: idxPcall++, code, score, source: 'pcall' });
  }

  // スコア順 (高い順) にソート → 最高スコアを best に
  results.sort((a, b) => b.score - a.score);
  // 重複除去 (同一コードを1件に)
  const seen = new Set();
  const unique = results.filter(r => {
    const key = r.code.substring(0, 120);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const best = unique[0] || null;
  return { all: unique, best: best ? best.code : null };
}



// ════════════════════════════════════════════════════════════════════════
//  YAJU Deobfuscator Engine v3
//  全20項目実装版
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
//  #19  seenCodeCache  — SHA1ハッシュによる重複解析防止
// ────────────────────────────────────────────────────────────────────────
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
class SymbolicEnv {
  constructor(parent=null){ this.vars=new Map(); this.parent=parent; }
  get(name){ if(this.vars.has(name))return this.vars.get(name); if(this.parent)return this.parent.get(name); return null; }
  set(name,entry){ this.vars.set(name,entry); }
  child(){ return new SymbolicEnv(this); }
}

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
function evaluateExpressions(code) {
  let modified = code, found = false;
  let prev, iters = 0;
  do {
    prev = modified;
    modified = modified.replace(/\(\s*([\d.]+)\s*([\+\-\*\/\%])\s*([\d.]+)\s*\)/g, (_, a, op, b) => {
      const result = evalSimpleExpr(`${a}${op}${b}`);
      if (result === null) return _;
      found = true; return String(result);
    });
  } while (modified !== prev && ++iters < 20);
  modified = modified.replace(/\[\s*([\d\s+\-*\/%().]+)\s*\]/g, (match, expr) => {
    const result = evalSimpleExpr(expr);
    if (result === null) return match;
    found = true; return `[${result}]`;
  });
  let concatIter = 0;
  while (/"((?:[^"\\]|\\.)*)"\s*\.\.\s*"((?:[^"\\]|\\.)*)"/g.test(modified) && concatIter++ < 40) {
    modified = modified.replace(/"((?:[^"\\]|\\.)*)"\s*\.\.\s*"((?:[^"\\]|\\.)*)"/g, (_, a, b) => { found = true; return `"${a}${b}"`; });
  }
  if (!found) return { success: false, error: '評価できる式がありませんでした', method: 'eval_expressions' };
  return { success: true, result: modified, method: 'eval_expressions' };
}

// ────────────────────────────────────────────────────────────────────────
//  #3  splitStrings  — 連続文字列連結を1つにまとめる
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
function constantArrayResolver(code, env) {
  env=env||new SymbolicEnv();
  let modified=code, found=false;
  let passCount=0;
  while(passCount++<12){
    let changed=false;
    const arrayPattern=/local\s+(\w+)\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}/g;
    let match; const snapshot=modified;
    while((match=arrayPattern.exec(snapshot))!==null){
      const varName=match[1],content=match[2];
      const elements=parseLuaArrayElements(content);
      if(elements.length<1) continue;
      const values=elements.map(e=>{
        const n=evalLuaNumExpr(e.trim()); if(n!==null) return n;
        const s=stripLuaString(e.trim()); if(s!==null) return s;
        return null;
      });
      if(values.some(v=>v===null)) continue;
      env.set(varName,{type:'table',value:values});
      const esc=varName.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
      const indexRe=new RegExp(esc+'\\[([^\\]]+)\\]','g');
      modified=modified.replace(indexRe,(fullMatch,indexExpr)=>{
        const idx=evalExprWithEnv(indexExpr,env);
        if(idx===null||typeof idx!=='number') return fullMatch;
        const rounded=Math.round(idx);
        if(rounded<1||rounded>values.length) return fullMatch;
        found=true; changed=true;
        const v=values[rounded-1];
        if(typeof v==='string') return `"${v.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`;
        return String(v);
      });
    }
    if(!changed) break;
  }
  if(!found) return { success:false, error:'ConstantArrayパターンが見つかりません', method:'constant_array' };
  return { success:true, result:modified, method:'constant_array' };
}
// 後方互換
function deobfuscateConstantArray(code){ return constantArrayResolver(code); }

// ────────────────────────────────────────────────────────────────────────
//  #7  constantCallEvaluator  — tonumber/tostring の定数呼び出しを変換
// ────────────────────────────────────────────────────────────────────────
function constantCallEvaluator(code) {
  let modified=code, found=false;
  // tonumber("123") -> 123, tonumber("0xff") -> 255
  modified=modified.replace(/\btonumber\s*\(\s*"([^"]+)"\s*(?:,\s*(\d+))?\s*\)/g,(_,s,base)=>{
    const n=parseInt(s,base?parseInt(base):10);
    if(isNaN(n)) return _;
    found=true; return String(n);
  });
  modified=modified.replace(/\btonumber\s*\(\s*'([^']+)'\s*(?:,\s*(\d+))?\s*\)/g,(_,s,base)=>{
    const n=parseInt(s,base?parseInt(base):10);
    if(isNaN(n)) return _;
    found=true; return String(n);
  });
  // tostring(123) -> "123"
  modified=modified.replace(/\btostring\s*\(\s*(-?\d+(?:\.\d+)?)\s*\)/g,(_,n)=>{
    found=true; return `"${n}"`;
  });
  if(!found) return { success:false, error:'tonumber/tostringの定数呼び出しが見つかりません', method:'constant_call' };
  return { success:true, result:modified, method:'constant_call' };
}

// ────────────────────────────────────────────────────────────────────────
//  #8  mathEvaluator  — math.* の引数が定数なら結果に置換
// ────────────────────────────────────────────────────────────────────────
function mathEvaluator(code) {
  let modified=code, found=false;
  const fns=['floor','ceil','abs','sqrt','max','min'];
  for(const fn of fns){
    const re=new RegExp(`math\\.${fn}\\s*\\(([^)]+)\\)`,'g');
    modified=modified.replace(re,(match,args)=>{
      const argList=splitByComma(args).map(a=>evalLuaNumExpr(a.trim()));
      if(argList.some(v=>v===null)) return match;
      let result;
      if(fn==='floor') result=Math.floor(argList[0]);
      else if(fn==='ceil') result=Math.ceil(argList[0]);
      else if(fn==='abs') result=Math.abs(argList[0]);
      else if(fn==='sqrt') result=Math.sqrt(argList[0]);
      else if(fn==='max') result=Math.max(...argList);
      else if(fn==='min') result=Math.min(...argList);
      if(result===undefined||!isFinite(result)) return match;
      found=true;
      return Number.isInteger(result)?String(result):result.toFixed(6);
    });
  }
  if(!found) return { success:false, error:'math.*の定数呼び出しが見つかりません', method:'math_eval' };
  return { success:true, result:modified, method:'math_eval' };
}

// ────────────────────────────────────────────────────────────────────────
//  #9  deadBranchRemover  — if true/false の不要分岐を削除
// ────────────────────────────────────────────────────────────────────────
function deadBranchRemover(code) {
  let modified=code, found=false;
  // if true then ... end  → 中身だけ残す
  modified=modified.replace(/\bif\s+true\s+then\s+([\s\S]*?)\s*end\b/g,(_,body)=>{ found=true; return body.trim(); });
  // if false then ... end  → 完全削除
  modified=modified.replace(/\bif\s+false\s+then\s+[\s\S]*?\s*end\b/g,()=>{ found=true; return ''; });
  // if true then ... else ... end → then節だけ残す
  modified=modified.replace(/\bif\s+true\s+then\s+([\s\S]*?)\s*else\s+[\s\S]*?\s*end\b/g,(_,thenPart)=>{ found=true; return thenPart.trim(); });
  // if false then ... else ... end → else節だけ残す
  modified=modified.replace(/\bif\s+false\s+then\s+[\s\S]*?\s*else\s+([\s\S]*?)\s*end\b/g,(_,elsePart)=>{ found=true; return elsePart.trim(); });
  // while false do ... end → 削除
  modified=modified.replace(/\bwhile\s+false\s+do\s+[\s\S]*?\s*end\b/g,()=>{ found=true; return ''; });
  // repeat ... until true → 1回実行（内容だけ残す）
  modified=modified.replace(/\brepeat\s+([\s\S]*?)\s*until\s+true\b/g,(_,body)=>{ found=true; return body.trim(); });
  if(!found) return { success:false, error:'デッドブランチが見つかりません', method:'dead_branch' };
  return { success:true, result:modified, method:'dead_branch' };
}

// ────────────────────────────────────────────────────────────────────────
//  #10  junkAssignmentCleaner  — 無意味代入・自己代入を削除
// ────────────────────────────────────────────────────────────────────────
function junkAssignmentCleaner(code) {
  let modified=code, found=false;
  // local a = a  (自己代入)
  modified=modified.replace(/local\s+(\w+)\s*=\s*\1\s*[\n;]/g,(_,name)=>{ found=true; return ''; });
  // local _ = ... (アンダースコア変数への代入)
  modified=modified.replace(/local\s+_\s*=\s*[^\n;]+[\n;]/g,()=>{ found=true; return ''; });
  // 連続する空行を1行に圧縮
  modified=modified.replace(/\n{3,}/g,'\n\n');
  if(!found) return { success:false, error:'ジャンク代入が見つかりません', method:'junk_clean' };
  return { success:true, result:modified, method:'junk_clean' };
}

// ────────────────────────────────────────────────────────────────────────
//  #11  duplicateConstantReducer  — 重複定数を1つにまとめる
// ────────────────────────────────────────────────────────────────────────
function duplicateConstantReducer(code) {
  let modified=code, found=false;
  // 同じ string.char(...) が3回以上出現する場合に変数化
  const scMap=new Map();
  modified.replace(/string\.char\([^)]+\)/g,m=>{ scMap.set(m,(scMap.get(m)||0)+1); });
  for(const [expr,count] of scMap) {
    if(count<3) continue;
    const varName=`_sc${Math.abs(hashCode(expr)&0xffff).toString(16)}`;
    // 変数宣言を先頭に追加し、使用箇所を置換
    const escapedExpr=expr.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    const re=new RegExp(escapedExpr,'g');
    if(re.test(modified)){
      modified=`local ${varName}=${expr}\n`+modified.replace(re,varName);
      found=true;
    }
  }
  if(!found) return { success:false, error:'重複定数が見つかりません', method:'dup_reduce' };
  return { success:true, result:modified, method:'dup_reduce' };
}

// ────────────────────────────────────────────────────────────────────────
//  #12  sandboxFilter  — 危険関数除去 + サイズ制限
// ────────────────────────────────────────────────────────────────────────
const MAX_DYNAMIC_SIZE = 512 * 1024; // 512KB
const DANGEROUS_PATTERNS = [
  /\bos\.execute\s*\(/g,
  /\bio\.popen\s*\(/g,
  /\bio\.open\s*\([^,)]+,\s*["']w/g,
  /\brequire\s*\(\s*["']socket/g,
  /\bloadfile\s*\(/g,
  /\bdofile\s*\(/g,
  /\bpackage\.loadlib\s*\(/g,
];
function sandboxFilter(code) {
  if(code.length>MAX_DYNAMIC_SIZE)
    return { safe:false, reason:`コードが大きすぎます (${(code.length/1024).toFixed(1)}KB > 512KB)`, code };
  let filtered=code;
  const removed=[];
  for(const pat of DANGEROUS_PATTERNS){
    if(pat.test(filtered)){
      filtered=filtered.replace(pat,m=>{ removed.push(m.replace(/\(/,'')); return '--[[REMOVED]]--'; });
      pat.lastIndex=0;
    }
  }
  return { safe:true, code:filtered, removed };
}

// ────────────────────────────────────────────────────────────────────────
//  #14  vmDetector  — while true do opcode=... のVMパターン検出
// ────────────────────────────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════════
//  BLOCK 2: vmDetector強化 / vmHookBootstrap / injectVmHook (#19-#33)
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
//  #20-#22  vmDetector 強化版 — MoonSec / Luraph / WereDev 検出
// ────────────────────────────────────────────────────────────────────────
function vmDetector(code) {
  const hints = [];

  // ── WereDev (#22) ──────────────────────────────────────────────────
  const weredevPatterns = [
    { re: /bytecode\s*\[\s*ip\s*\]/,                                  desc: 'WereDev: bytecode[ip]' },
    { re: /dispatch\s*\[\s*inst\s*\[\s*1\s*\]\s*\]/,                 desc: 'WereDev: dispatch[inst[1]]' },
    { re: /\bvm_loop\b/,                                              desc: 'WereDev: vm_loop' },
    { re: /while\s+true\s+do[\s\S]{0,400}bytecode\s*\[\s*ip\s*\]/i,  desc: 'WereDev: while-true+bytecode[ip]' },
    { re: /local\s+inst\s*=\s*bytecode\s*\[\s*ip\s*\]/,              desc: 'WereDev: local inst=bytecode[ip]' },
    { re: /inst\s*\[\s*1\s*\]/,                                       desc: 'WereDev: inst[1]' },
    { re: /ip\s*=\s*ip\s*\+\s*1/,                                    desc: 'WereDev: ip+1' },
  ];

  // ── MoonSec (#20) ──────────────────────────────────────────────────
  const moonSecPatterns = [
    { re: /MoonSec/,                                                  desc: 'MoonSec: MoonSec識別子' },
    { re: /MSVM/,                                                     desc: 'MoonSec: MSVM' },
    { re: /_ENV\s*\[.+\]/,                                            desc: 'MoonSec: _ENV[key]アクセス' },
    { re: /dispatch\s*\[opcode\]/,                                    desc: 'MoonSec: dispatch[opcode]' },
    { re: /stk\s*\[top\]|stk\s*\[top\s*-/,                          desc: 'MoonSec: stack top操作' },
  ];

  // ── Luraph (#21) ───────────────────────────────────────────────────
  const luraphPatterns = [
    { re: /LPH_String/,                                               desc: 'Luraph: LPH_String' },
    { re: /LPH_GetEnv/,                                               desc: 'Luraph: LPH_GetEnv' },
    { re: /LPH_JIT/,                                                  desc: 'Luraph: LPH_JIT' },
    { re: /\bLPH\b/,                                                  desc: 'Luraph: LPH識別子' },
  ];

  // ── 汎用VM ─────────────────────────────────────────────────────────
  const genericPatterns = [
    { re: /while\s+true\s+do[\s\S]{0,200}opcode/i,  desc: 'generic: while-true opcode' },
    { re: /\bopcode\b.*\bInstructions\b/s,           desc: 'generic: opcode+Instructions' },
    { re: /local\s+\w+\s*=\s*Instructions\s*\[/,    desc: 'generic: Instructions配列' },
    { re: /\bProto\b[\s\S]{0,100}\bupValues\b/s,     desc: 'generic: Proto/upValues' },
    { re: /\bVStack\b|\bVEnv\b|\bVPC\b/,             desc: 'generic: 仮想スタック' },
    { re: /if\s+opcode\s*==\s*\d+\s*then/,           desc: 'generic: opcodeディスパッチ' },
    { re: /\{(\s*\d+\s*,){20,}/,                     desc: 'generic: 大規模数値テーブル' },
    { re: /\bbit\.bxor\b|\bbit\.band\b|\bbit32\./,   desc: 'generic: ビット演算' },
  ];

  let weredevScore = 0;
  let moonSecScore = 0;
  let luraphScore  = 0;

  for (const p of weredevPatterns) {
    if (p.re.test(code)) { hints.push(p.desc); weredevScore++; }
  }
  for (const p of moonSecPatterns) {
    if (p.re.test(code)) { hints.push(p.desc); moonSecScore++; }
  }
  for (const p of luraphPatterns) {
    if (p.re.test(code)) { hints.push(p.desc); luraphScore++; }
  }
  if (/return\s*\(function\s*\([^)]*\)/s.test(code)) hints.push('自己実行関数ラッパー');
  for (const p of genericPatterns) {
    if (p.re.test(code)) hints.push(p.desc);
  }

  const strings = [];
  const strPattern = /"([^"\\]{4,}(?:\\.[^"\\]*)*)"/g;
  let ms;
  while ((ms = strPattern.exec(code)) !== null) {
    if (ms[1].length > 4) strings.push(ms[1]);
  }
  if (strings.length > 0) hints.push(`${strings.length}件の文字列`);

  const isWereDev  = weredevScore >= 2;
  const isMoonSec  = moonSecScore >= 2;
  const isLuraph   = luraphScore  >= 1;
  const isVm       = hints.length >= 2;

  return { isVm, isWereDev, isMoonSec, isLuraph,
    weredevScore, moonSecScore, luraphScore,
    hints, strings: strings.slice(0, 50), method: 'vm_detect' };
}

function deobfuscateVmify(code) {
  const hints = [];
  if (/return\s*\(function\s*\([^)]*\)/s.test(code)) hints.push('VMラッパー検出');
  if (/\bInstructions\b|\bProto\b|\bupValues\b/i.test(code)) hints.push('Luaバイトコード構造を検出');
  const strings = [];
  const strPattern = /"([^"\\]{4,}(?:\\.[^"\\]*)*)"/g;
  let m;
  while ((m = strPattern.exec(code)) !== null) { if (m[1].length > 4) strings.push(m[1]); }
  if (strings.length > 0) hints.push(`${strings.length}件の文字列リテラルを抽出`);
  if (/\{(\s*\d+\s*,){8,}/.test(code)) hints.push('大規模バイトコードテーブルを検出');
  if (hints.length === 0) return { success: false, error: 'Vmifyパターンが検出されませんでした', method: 'vmify' };
  return { success: true, result: code, hints, strings: strings.slice(0, 50), warning: 'Vmify完全解読には動的実行を推奨', method: 'vmify' };
}

// ────────────────────────────────────────────────────────────────────────
//  #26/#27/#28/#29  vmHookBootstrap 強化版
// ────────────────────────────────────────────────────────────────────────
const vmHookBootstrap = `
-- ══ YAJU VM Hook Bootstrap v4 ══

-- ── 旧 __vmhook 互換テーブル ──────────────────────────────────────────
__vm_logs      = {}
__vm_log_count = 0
__vm_max_logs  = 5000

-- ── [2] __vmtrace: instruction trace テーブル ────────────────────────
__vmtrace       = {}
__vmtrace_count = 0
__vmtrace_max   = 10000   -- 最大 10000 命令

-- ── [2] __vmtrace_hook: opcode/a/b/c を trace に蓄積 ─────────────────
-- 呼び出し規約: __vmtrace_hook(ip, opcode, a, b, c)
function __vmtrace_hook(ip, opcode, a, b, c)
  if __vmtrace_count >= __vmtrace_max then return end
  __vmtrace_count = __vmtrace_count + 1
  __vmtrace[__vmtrace_count] = {
    i  = __vmtrace_count,
    ip = ip  or 0,
    op = opcode,
    a  = a,
    b  = b,
    c  = c,
  }
end

-- ── 旧 __vmhook (互換) ────────────────────────────────────────────────
function __vmhook(ip, inst, stack, reg)
  if __vm_log_count >= __vm_max_logs then return end
  __vm_log_count = __vm_log_count + 1
  local entry = { ip = ip, ts = __vm_log_count }
  if type(inst) == "table" then
    entry.op   = inst[1]; entry.arg1 = inst[2]
    entry.arg2 = inst[3]; entry.arg3 = inst[4]
    __vmtrace_hook(ip, inst[1], inst[2], inst[3], inst[4])
  elseif type(inst) == "number" then
    entry.op = inst
    __vmtrace_hook(ip, inst, nil, nil, nil)
  end
  table.insert(__vm_logs, entry)
end

-- ── [2] while dispatch ループ自己検出フック ───────────────────────────
-- WeredevのVMは通常:
--   local inst = bytecode[ip]  → opcode=inst[1], A=inst[2], B=inst[3], C=inst[4]
-- または:
--   local opcode = inst[1]     → dispatch[opcode](...)
-- の形を取る。
-- debug.sethook で "line" イベントをトリガーして変数を覗く方法は
-- Lua5.1では使えないため、代わりに __index メタメソッドで
-- bytecode テーブルへのアクセスをインターセプトする。
--
-- アプローチ: グローバルに存在しうる bytecode / instructions / proto
-- テーブルに __index フックを仕込み、アクセスのたびに trace する。
-- ──────────────────────────────────────────────────────────────────────
local function __install_vm_intercept()
  -- 候補テーブル名（WereDev / MoonSec / Luraph で使われる変数名）
  local candidates = {
    "bytecode","instructions","Bytecode","Instructions",
    "proto","Proto","code","Code","ops","Ops",
  }
  for _, name in ipairs(candidates) do
    local tbl = rawget(_G, name)
    if type(tbl) == "table" and #tbl > 8 then
      -- 既にメタテーブルが設定されている場合はスキップ
      local ok, mt = pcall(getmetatable, tbl)
      if ok and mt == nil then
        local orig_index = nil
        local new_mt = {
          __index = function(t, k)
            local v = rawget(t, k)
            -- アクセスが数値キーで値がテーブルなら instruction と見なす
            if type(k) == "number" and type(v) == "table" then
              __vmtrace_hook(k, v[1], v[2], v[3], v[4])
            elseif type(k) == "number" and type(v) == "number" then
              __vmtrace_hook(k, v, nil, nil, nil)
            end
            return v
          end
        }
        -- setmetatable はエラーになりうるので pcall で保護
        pcall(setmetatable, tbl, new_mt)
      end
    end
  end
end
-- 実行開始後に少し遅延してインターセプトを試みる
-- (VMの初期化が完了するのを待つため coroutine.wrap で遅延)
local __intercept_installed = false
local __orig_coroutine_wrap = coroutine and coroutine.wrap
if __orig_coroutine_wrap then
  pcall(function()
    local co = coroutine.create(function()
      coroutine.yield()
      if not __intercept_installed then
        __intercept_installed = true
        __install_vm_intercept()
      end
    end)
    coroutine.resume(co)
  end)
end
-- 即時もトライ（すでにテーブルが存在する場合）
pcall(__install_vm_intercept)
-- ══ Bootstrap End ══
`;

// ────────────────────────────────────────────────────────────────────────
//  #28  vmDumpFooter — __VMLOG__ 形式で stdout に出力
// ────────────────────────────────────────────────────────────────────────
const vmDumpFooter = `
-- ══ YAJU VM Dump Footer v4 ══

-- ── [1] string.char キャプチャログ出力 ────────────────────────────────
-- VM bytecode が string.char で構築されたバイト列をログに出す
if __strchar_count and __strchar_count > 0 then
  io.write("\\n__STRCHAR_START__\\n")
  for i = 1, math.min(__strchar_count, __strchar_max or 500) do
    local s = __strchar_log[i]
    if s then
      -- 各バイトを10進数コンマ区切りで出力 (バイナリ安全)
      local bytes = {}
      for j = 1, #s do
        bytes[j] = tostring(s:byte(j))
      end
      io.write(tostring(i) .. "\\t" .. (#s) .. "\\t" .. table.concat(bytes, ",") .. "\\n")
    end
  end
  io.write("__STRCHAR_END__\\t" .. tostring(__strchar_count) .. "\\n")
  io.flush()
end

-- ── [1] table.concat キャプチャログ出力 ──────────────────────────────
if __tconcat_count and __tconcat_count > 0 then
  io.write("\\n__TCONCAT_START__\\n")
  for i = 1, math.min(__tconcat_count, __tconcat_max or 500) do
    local s = __tconcat_log[i]
    if s then
      local bytes = {}
      for j = 1, #s do bytes[j] = tostring(s:byte(j)) end
      io.write(tostring(i) .. "\\t" .. (#s) .. "\\t" .. table.concat(bytes, ",") .. "\\n")
    end
  end
  io.write("__TCONCAT_END__\\t" .. tostring(__tconcat_count) .. "\\n")
  io.flush()
end

-- ── 旧 __VMLOG__ 形式出力 (既存 parseVmLogs との互換) ────────────────
if __vm_log_count and __vm_log_count > 0 then
  for i, v in ipairs(__vm_logs) do
    local op   = tostring(v.op   or "nil")
    local arg1 = tostring(v.arg1 or "nil")
    local arg2 = tostring(v.arg2 or "nil")
    local arg3 = tostring(v.arg3 or "nil")
    print("__VMLOG__\\t" .. tostring(v.ip) .. "\\t" .. op .. "\\t" .. arg1 .. "\\t" .. arg2 .. "\\t" .. arg3)
  end
  print("__VMLOG_END__\\t" .. tostring(__vm_log_count))
end

-- ── [3] __VMTRACE_START__ / __VMTRACE_END__: instruction trace ダンプ ─
-- フォーマット: idx \\t ip \\t op \\t a \\t b \\t c (タブ区切り)
if __vmtrace_count and __vmtrace_count > 0 then
  io.write("\\n__VMTRACE_START__\\n")
  for i = 1, __vmtrace_count do
    local v = __vmtrace[i]
    if v then
      local ip_s = tostring(v.ip or 0)
      local op_s = tostring(v.op or "nil")
      local a_s  = tostring(v.a  or "nil")
      local b_s  = tostring(v.b  or "nil")
      local c_s  = tostring(v.c  or "nil")
      io.write(tostring(i).."\\t"..ip_s.."\\t"..op_s.."\\t"..a_s.."\\t"..b_s.."\\t"..c_s.."\\n")
    end
  end
  io.write("__VMTRACE_END__\\t" .. tostring(__vmtrace_count) .. "\\n")
  io.flush()
end
-- ══ Dump End ══
`;

// ────────────────────────────────────────────────────────────────────────
//  #24/#30/#31/#32/#33  injectVmHook 強化版
//  — WereDev/MoonSec/Luraph それぞれに対応した注入
// ────────────────────────────────────────────────────────────────────────
function injectVmHook(code, vmInfo) {
  let modified = code;
  let injected  = false;
  const type_   = vmInfo || {};

  // [2] WereDev パターン: local inst = bytecode[ip] の直後に trace hook を注入
  // opcode は inst[1], a=inst[2], b=inst[3], c=inst[4]
  if (!injected || type_.isWereDev) {
    modified = modified.replace(
      /(local\s+inst\s*=\s*bytecode\s*\[\s*ip\s*\][^\n]*\n)/g,
      (match) => {
        injected = true;
        return match
          + '  __vmtrace_hook(ip, inst and inst[1], inst and inst[2], inst and inst[3], inst and inst[4])\n'
          + '  __vmhook(ip, inst)\n';
      }
    );
  }

  // [2] MoonSec パターン: dispatch[opcode]( の直前に trace hook を注入
  if (!injected || type_.isMoonSec) {
    modified = modified.replace(
      /(dispatch\s*\[\s*opcode\s*\]\s*\()/g,
      (match) => {
        injected = true;
        return `__vmtrace_hook(ip, opcode, nil, nil, nil); __vmhook(ip, opcode); ` + match;
      }
    );
    modified = modified.replace(
      /(dispatch\s*\[\s*inst\s*\[\s*1\s*\]\s*\]\s*\()/g,
      (match) => {
        injected = true;
        return `__vmtrace_hook(ip, inst and inst[1], inst and inst[2], inst and inst[3], inst and inst[4]); __vmhook(ip, inst); ` + match;
      }
    );
  }

  // [2] Luraph パターン
  if (type_.isLuraph) {
    modified = modified.replace(
      /\bLPH_GetEnv\s*\(/g,
      (match) => { injected = true; return `__vmtrace_hook(0, "LPH_GetEnv", nil, nil, nil); __vmhook(0, "LPH_GetEnv"); ` + match; }
    );
    modified = modified.replace(
      /\bLPH_String\s*\(/g,
      (match) => { injected = true; return `__vmtrace_hook(0, "LPH_String", nil, nil, nil); __vmhook(0, "LPH_String"); ` + match; }
    );
  }

  // [2] while true do / repeat until ループ直後への汎用注入
  modified = modified.replace(
    /(while\s+true\s+do\s*\n)/g,
    (match) => {
      injected = true;
      return match + '  __vmtrace_hook(ip, inst and inst[1] or opcode, inst and inst[2], inst and inst[3], inst and inst[4])\n'
                   + '  __vmhook(ip, inst, stack, reg)\n';
    }
  );
  modified = modified.replace(
    /(repeat\s*\n)/g,
    (match) => {
      injected = true;
      return match + '  __vmtrace_hook(ip, inst and inst[1] or opcode, inst and inst[2], inst and inst[3], inst and inst[4])\n'
                   + '  __vmhook(ip, inst, stack, reg)\n';
    }
  );

  // 汎用フォールバック: local opcode = の次行
  if (!injected) {
    modified = modified.replace(
      /(local\s+opcode\s*=\s*[^\n]+\n)/g,
      (match) => {
        injected = true;
        return match
          + '  __vmtrace_hook(ip, opcode, nil, nil, nil)\n'
          + '  __vmhook(ip, opcode)\n';
      }
    );
  }

  return { code: modified, injected };
}

// ────────────────────────────────────────────────────────────────────────
//  runLuaWithHooks  (#26: vmHookBootstrap を先頭に注入)
// ────────────────────────────────────────────────────────────────────────
function runLuaWithHooks(code) {
  return vmHookBootstrap + '\n' + code + '\n' + vmDumpFooter;
}


// ════════════════════════════════════════════════════════════════════════
//  BLOCK 3: VMログ解析 / 逆コンパイラ (#34-#54)
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
//  #34/#35  parseVmLogs 強化版 — split("\t") で構造化
// ────────────────────────────────────────────────────────────────────────
function parseVmLogs(stdout) {
  const vmTrace = [];
  const lines = stdout.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('__VMLOG__')) continue;
    // split("\t") で ip opcode arg1 arg2 を構造化
    const parts = trimmed.split('\t');
    if (parts.length < 3) continue;
    const ip   = parseInt(parts[1]) || 0;
    const op   = parts[2] !== 'nil' ? (isNaN(Number(parts[2])) ? parts[2] : parseInt(parts[2])) : null;
    const arg1 = parts[3] !== undefined && parts[3] !== 'nil'
      ? (isNaN(Number(parts[3])) ? parts[3] : parseInt(parts[3])) : null;
    const arg2 = parts[4] !== undefined && parts[4] !== 'nil'
      ? (isNaN(Number(parts[4])) ? parts[4] : parseInt(parts[4])) : null;
    const arg3 = parts[5] !== undefined && parts[5] !== 'nil'
      ? (isNaN(Number(parts[5])) ? parts[5] : parseInt(parts[5])) : null;
    vmTrace.push({ ip, op, arg1, arg2, arg3 });
  }
  return vmTrace;
}

// ────────────────────────────────────────────────────────────────────────
//  [4] parseVmTrace — __VMTRACE_START__ / __VMTRACE_END__ を検出して
//       instruction trace を構造化データとして取得する
// ────────────────────────────────────────────────────────────────────────
function parseVmTrace(stdout) {
  if (!stdout) return { entries: [], count: 0, found: false };

  const startMarker = '__VMTRACE_START__';
  const endMarker   = '__VMTRACE_END__';

  const startIdx = stdout.indexOf(startMarker);
  const endIdx   = stdout.indexOf(endMarker);

  // マーカーが存在しない場合は空で返す
  if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx) {
    return { entries: [], count: 0, found: false };
  }

  // マーカー間のテキストを切り出す
  const rawBlock = stdout.substring(startIdx + startMarker.length, endIdx).trim();
  if (!rawBlock) return { entries: [], count: 0, found: false };

  const entries = [];
  const lines = rawBlock.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // フォーマット: idx \t ip \t op \t a \t b \t c
    const parts = trimmed.split('\t');
    if (parts.length < 3) continue;

    const toVal = (s) => {
      if (s === undefined || s === 'nil') return null;
      const n = Number(s);
      return isNaN(n) ? s : (Number.isInteger(n) ? n : n);
    };

    const idx = parseInt(parts[0]) || 0;
    const ip  = toVal(parts[1]);
    const op  = toVal(parts[2]);
    const a   = toVal(parts[3]);
    const b   = toVal(parts[4]);
    const c   = toVal(parts[5]);

    entries.push({ idx, ip, op, a, b, c });
  }

  // __VMTRACE_END__ の後ろのカウント取得
  const endLine = stdout.substring(endIdx, stdout.indexOf('\n', endIdx));
  const countMatch = endLine.match(/__VMTRACE_END__\t(\d+)/);
  const reportedCount = countMatch ? parseInt(countMatch[1]) : entries.length;

  return { entries, count: reportedCount, found: true };
}

// ────────────────────────────────────────────────────────────────────────
//  [1] parseStrCharLog — __STRCHAR_START__ / __STRCHAR_END__ を解析して
//      string.char でキャプチャされた VM bytecode バイト列を取得する
// ────────────────────────────────────────────────────────────────────────
function parseStrCharLog(stdout) {
  if (!stdout) return { entries: [], count: 0, found: false };
  const startIdx = stdout.indexOf('__STRCHAR_START__');
  const endIdx   = stdout.indexOf('__STRCHAR_END__');
  if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx)
    return { entries: [], count: 0, found: false };

  const raw = stdout.substring(startIdx + '__STRCHAR_START__'.length, endIdx).trim();
  const entries = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    // フォーマット: idx \t len \t b0,b1,b2,...
    const parts = t.split('\t');
    if (parts.length < 3) continue;
    const idx  = parseInt(parts[0]) || 0;
    const len  = parseInt(parts[1]) || 0;
    const bytes = parts[2].split(',').map(n => parseInt(n)).filter(n => !isNaN(n));
    // バイト列を文字列に復元
    const str = bytes.map(b => String.fromCharCode(b)).join('');
    entries.push({ idx, len, bytes, str });
  }
  const countLine = stdout.substring(endIdx, stdout.indexOf('\n', endIdx));
  const countMatch = countLine.match(/__STRCHAR_END__\t(\d+)/);
  return { entries, count: countMatch ? parseInt(countMatch[1]) : entries.length, found: true };
}

// ────────────────────────────────────────────────────────────────────────
//  [1] parseTConcatLog — __TCONCAT_START__ / __TCONCAT_END__ を解析して
//      table.concat でキャプチャされた VM bytecode 結合文字列を取得する
// ────────────────────────────────────────────────────────────────────────
function parseTConcatLog(stdout) {
  if (!stdout) return { entries: [], count: 0, found: false };
  const startIdx = stdout.indexOf('__TCONCAT_START__');
  const endIdx   = stdout.indexOf('__TCONCAT_END__');
  if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx)
    return { entries: [], count: 0, found: false };

  const raw = stdout.substring(startIdx + '__TCONCAT_START__'.length, endIdx).trim();
  const entries = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const parts = t.split('\t');
    if (parts.length < 3) continue;
    const idx   = parseInt(parts[0]) || 0;
    const len   = parseInt(parts[1]) || 0;
    const bytes = parts[2].split(',').map(n => parseInt(n)).filter(n => !isNaN(n));
    const str   = bytes.map(b => String.fromCharCode(b)).join('');
    entries.push({ idx, len, bytes, str });
  }
  const countLine = stdout.substring(endIdx, stdout.indexOf('\n', endIdx));
  const countMatch = countLine.match(/__TCONCAT_END__\t(\d+)/);
  return { entries, count: countMatch ? parseInt(countMatch[1]) : entries.length, found: true };
}

// ────────────────────────────────────────────────────────────────────────
//  #36  saveVmTrace — vmトレースをJSONとして保存
// ────────────────────────────────────────────────────────────────────────
function saveVmTrace(vmTrace, suffix) {
  if (!vmTrace || vmTrace.length === 0) return null;
  try {
    const fname = path.join(tempDir, `vm_trace_${suffix || Date.now()}.json`);
    fs.writeFileSync(fname, JSON.stringify(vmTrace, null, 2), 'utf8');
    return fname;
  } catch { return null; }
}

// ────────────────────────────────────────────────────────────────────────
//  #37/#38/#39  vmTraceAnalyzer 強化版 — dispatch table推定 + 挙動推定
// ────────────────────────────────────────────────────────────────────────
const LUA51_OPCODES = {
  0:'MOVE',1:'LOADK',2:'LOADBOOL',3:'LOADNIL',4:'GETUPVAL',
  5:'GETGLOBAL',6:'GETTABLE',7:'SETGLOBAL',8:'SETUPVAL',9:'SETTABLE',
  10:'NEWTABLE',11:'SELF',12:'ADD',13:'SUB',14:'MUL',
  15:'DIV',16:'MOD',17:'POW',18:'UNM',19:'NOT',
  20:'LEN',21:'CONCAT',22:'JMP',23:'EQ',24:'LT',
  25:'LE',26:'TEST',27:'TESTSET',28:'CALL',29:'TAILCALL',
  30:'RETURN',31:'FORLOOP',32:'FORPREP',33:'TFORLOOP',34:'SETLIST',
  35:'CLOSE',36:'CLOSURE',37:'VARARG',
};

// opcode挙動カテゴリ
const OPCODE_CATEGORIES = {
  MOVE:'MOVE', LOADK:'CONST', LOADBOOL:'CONST', LOADNIL:'CONST',
  GETUPVAL:'LOAD', GETGLOBAL:'LOAD', GETTABLE:'LOAD',
  SETGLOBAL:'STORE', SETUPVAL:'STORE', SETTABLE:'STORE',
  NEWTABLE:'TABLE', SELF:'TABLE',
  ADD:'ARITH', SUB:'ARITH', MUL:'ARITH', DIV:'ARITH', MOD:'ARITH', POW:'ARITH',
  UNM:'ARITH', NOT:'ARITH', LEN:'ARITH', CONCAT:'ARITH',
  JMP:'JUMP', EQ:'JUMP', LT:'JUMP', LE:'JUMP', TEST:'JUMP', TESTSET:'JUMP',
  CALL:'CALL', TAILCALL:'CALL', RETURN:'RETURN',
  FORLOOP:'LOOP', FORPREP:'LOOP', TFORLOOP:'LOOP',
  SETLIST:'TABLE', CLOSE:'CLOSE', CLOSURE:'CLOSURE', VARARG:'VARARG',
};

function vmTraceAnalyzer(vmTrace) {
  if (!vmTrace || vmTrace.length === 0)
    return { success: false, error: 'vmTraceが空', opcodeMap: {} };

  // #37: opcode頻度カウント
  const freq = {};
  for (const e of vmTrace) {
    if (e.op === null || e.op === undefined) continue;
    const k = String(e.op);
    freq[k] = (freq[k] || 0) + 1;
  }
  const sorted = Object.entries(freq)
    .sort((a, b) => b[1] - a[1])
    .map(([op, count]) => ({ op: isNaN(Number(op)) ? op : parseInt(op), count }));

  // #38: dispatch table推定 — opcodeと名前のマッピング
  const dispatchTable = {};
  for (const { op } of sorted) {
    const n = parseInt(op);
    if (!isNaN(n) && LUA51_OPCODES[n]) dispatchTable[op] = LUA51_OPCODES[n];
  }

  // opcodeExecutionMap (名前付き)
  const opcodeExecutionMap = {};
  for (const [num, name] of Object.entries(LUA51_OPCODES)) {
    const entries = vmTrace.filter(t => String(t.op) === String(num));
    if (entries.length > 0) {
      opcodeExecutionMap[name] = {
        opcode: parseInt(num), count: entries.length,
        category: OPCODE_CATEGORIES[name] || 'UNKNOWN',
        sampleArgs: entries.slice(0, 3).map(e => [e.arg1, e.arg2, e.arg3]),
      };
    }
  }

  // #39: カテゴリ別挙動推定
  const behaviorSummary = {};
  for (const [name, info] of Object.entries(opcodeExecutionMap)) {
    const cat = info.category;
    behaviorSummary[cat] = (behaviorSummary[cat] || 0) + info.count;
  }

  // IP変化からCFG情報
  const ipJumps = [];
  for (let i = 1; i < vmTrace.length; i++) {
    const d = vmTrace[i].ip - vmTrace[i-1].ip;
    if (d !== 1 && d !== 0) ipJumps.push({ from: vmTrace[i-1].ip, to: vmTrace[i].ip, delta: d });
  }

  const opcodeIndex = { position: 1, confidence: 'high', note: 'inst[1]=opcode' };
  const opcodeMap = { map: dispatchTable, opcodeIndex, opcodeExecutionMap };

  return {
    success: true,
    totalInstructions: vmTrace.length,
    uniqueOpcodes: sorted.length,
    opcodeFrequency: sorted.slice(0, 20),
    opcodeMap,
    dispatchTable,
    behaviorSummary,
    ipJumps: ipJumps.slice(0, 30),
    method: 'vm_trace_analyze',
  };
}

// ────────────────────────────────────────────────────────────────────────
//  #13/#14  staticCharDecoder / tableConcat 静的デコーダ
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
function vmDecompiler(vmTrace, bytecodeDump, opcodeMap) {
  if (!vmTrace || vmTrace.length === 0)
    return { success: false, error: 'vmTraceが空', pseudoCode: '', method: 'vm_decompile' };

  const map       = (opcodeMap && opcodeMap.map) || {};
  const exMap     = (opcodeMap && opcodeMap.opcodeExecutionMap) || {};
  const catMap    = {};
  for (const [name, info] of Object.entries(exMap)) catMap[info.opcode] = info.category;

  // ── #49/#50: 定数テーブル抽出 ────────────────────────────────────────
  const constTables = {};
  for (const [tname, nums] of Object.entries(bytecodeDump || {})) {
    constTables[tname] = nums;
  }

  // ── #41: 中間命令(IR)に変換 ─────────────────────────────────────────
  const ir = [];
  // map は dispatchTable(string key) か LUA51_OPCODES(number key) を自動選択
  const resolvedMap = (map && Object.keys(map).length > 0) ? map : LUA51_OPCODES;
  for (const entry of vmTrace) {
    const { ip, op, arg1, arg2, arg3 } = entry;
    const opName = (op !== null && op !== undefined)
      ? (resolvedMap[String(op)] || resolvedMap[op] || `OP_${op}`) : 'UNKNOWN';
    const cat    = catMap[String(op)] || catMap[op] || OPCODE_CATEGORIES[opName] || 'UNKNOWN';
    ir.push({ ip, opName, cat, op, arg1, arg2, arg3 });
  }

  // ── #42: CFG構築 (IPベースの基本ブロック分割) ─────────────────────
  // leaders: IPセットを ir[0].ipから始め、全IPを登録
  const firstIp = ir.length > 0 ? ir[0].ip : 0;
  const leaders   = new Set([firstIp]);
  // 全IPをリーダー候補として追加
  for (const inst of ir) leaders.add(inst.ip);
  const jumpTargets = new Set();
  for (const inst of ir) {
    if (['JUMP','EQ','LT','LE','TEST','TESTSET'].includes(inst.cat)) {
      // JMP offset から飛び先を計算
      if (inst.opName === 'JMP' && inst.arg2 !== null) {
        const target = inst.ip + 1 + inst.arg2;
        leaders.add(target);
        jumpTargets.add(target);
      }
      leaders.add(inst.ip + 1);
    }
    if (inst.cat === 'LOOP') {
      leaders.add(inst.ip);
      if (inst.arg2 !== null) leaders.add(inst.ip + 1 + inst.arg2);
    }
  }

  // ── #43: 基本ブロック作成 ──────────────────────────────────────────
  const blocks = [];
  let currentBlock = null;
  for (const inst of ir) {
    if (leaders.has(inst.ip)) {
      if (currentBlock) blocks.push(currentBlock);
      currentBlock = { startIp: inst.ip, instructions: [], isLoopTarget: jumpTargets.has(inst.ip) };
    }
    if (currentBlock) currentBlock.instructions.push(inst);
  }
  if (currentBlock) blocks.push(currentBlock);

  // ── #44-#48: 基本ブロックから疑似Luaコード生成 ──────────────────────
  const lines = [];
  lines.push('-- ══ YAJU VM Decompiled (疑似Lua) ══');
  if (Object.keys(constTables).length > 0) {
    // #50: 定数テーブルを local const = {...} として出力
    for (const [tname, nums] of Object.entries(constTables)) {
      lines.push(`local ${tname}_const = {${nums.slice(0,16).join(',')}${nums.length > 16 ? ',...' : ''}}`);
    }
    lines.push('');
  }

  // レジスタ名マッピング (#48)
  const regName = (n) => n !== null ? `v${n}` : '_';

  let indentLevel = 0;
  const indent = () => '  '.repeat(indentLevel);
  const prevIp = { val: -1 };

  for (const block of blocks) {
    if (block.isLoopTarget)
      lines.push(`${indent()}::lbl_${block.startIp}::`);

    for (const inst of block.instructions) {
      const { ip, opName, cat, arg1, arg2, arg3 } = inst;
      let line = '';

      // #44: ジャンプ命令を if/while/for に復元
      // #45: スタック操作を変数に復元
      // #46: 算術opcode を + - * / に復元
      // #47: CALL opcode を関数呼び出しに復元
      // #48: VM register を Lua ローカル変数に変換
      switch (opName) {
        case 'MOVE':     line = `local ${regName(arg1)} = ${regName(arg2)}  -- MOVE`; break;
        case 'LOADK':    line = `local ${regName(arg1)} = K[${arg2}]  -- LOADK`; break;
        case 'LOADBOOL': line = `local ${regName(arg1)} = ${arg2 ? 'true' : 'false'}  -- LOADBOOL`; indentLevel=Math.max(0,indentLevel); break;
        case 'LOADNIL':  line = `for __i=${arg1},(${arg2}) do local _v${arg1}=nil end  -- LOADNIL`; break;
        case 'GETGLOBAL':line = `local ${regName(arg1)} = _G[K[${arg2}]]  -- GETGLOBAL`; break;
        case 'SETGLOBAL':line = `_G[K[${arg2}]] = ${regName(arg1)}  -- SETGLOBAL`; break;
        case 'GETTABLE': line = `local ${regName(arg1)} = ${regName(arg2)}[K_or_R(${arg3})]  -- GETTABLE`; break;
        case 'SETTABLE': line = `${regName(arg1)}[K_or_R(${arg2})] = K_or_R(${arg3})  -- SETTABLE`; break;
        case 'NEWTABLE': line = `local ${regName(arg1)} = {}  -- NEWTABLE`; break;
        // #46: 算術
        case 'ADD':    line = `local ${regName(arg1)} = ${regName(arg2)} + ${regName(arg3)}  -- ADD`; break;
        case 'SUB':    line = `local ${regName(arg1)} = ${regName(arg2)} - ${regName(arg3)}  -- SUB`; break;
        case 'MUL':    line = `local ${regName(arg1)} = ${regName(arg2)} * ${regName(arg3)}  -- MUL`; break;
        case 'DIV':    line = `local ${regName(arg1)} = ${regName(arg2)} / ${regName(arg3)}  -- DIV`; break;
        case 'MOD':    line = `local ${regName(arg1)} = ${regName(arg2)} % ${regName(arg3)}  -- MOD`; break;
        case 'POW':    line = `local ${regName(arg1)} = ${regName(arg2)} ^ ${regName(arg3)}  -- POW`; break;
        case 'UNM':    line = `local ${regName(arg1)} = -${regName(arg2)}  -- UNM`; break;
        case 'NOT':    line = `local ${regName(arg1)} = not ${regName(arg2)}  -- NOT`; break;
        case 'LEN':    line = `local ${regName(arg1)} = #${regName(arg2)}  -- LEN`; break;
        case 'CONCAT': {
          const parts = [];
          for (let i = arg2; i <= arg3; i++) parts.push(regName(i));
          line = `local ${regName(arg1)} = ${parts.join(' .. ')}  -- CONCAT`;
          break;
        }
        // #44: ジャンプ命令
        case 'JMP': {
          const target = ip + 1 + (arg2 || 0);
          line = `goto lbl_${target}  -- JMP target=${target}`;
          break;
        }
        case 'EQ':  line = `if (${regName(arg2)} == ${regName(arg3)}) ~= ${arg1?'true':'false'} then goto lbl_${ip+2} end  -- EQ`; break;
        case 'LT':  line = `if (${regName(arg2)} < ${regName(arg3)}) ~= ${arg1?'true':'false'} then goto lbl_${ip+2} end  -- LT`; break;
        case 'LE':  line = `if (${regName(arg2)} <= ${regName(arg3)}) ~= ${arg1?'true':'false'} then goto lbl_${ip+2} end  -- LE`; break;
        case 'TEST':    line = `if not ${regName(arg1)} then goto lbl_${ip+2} end  -- TEST`; break;
        case 'TESTSET': line = `if ${regName(arg2)} then ${regName(arg1)}=${regName(arg2)} else goto lbl_${ip+2} end  -- TESTSET`; break;
        // #47: CALL
        case 'CALL': {
          const nargs  = (arg2 || 1) - 1;
          const nret   = (arg3 || 1) - 1;
          const args_  = Array.from({length: nargs}, (_, i) => regName(arg1 + 1 + i));
          const rets   = Array.from({length: Math.max(1, nret)}, (_, i) => regName(arg1 + i));
          line = `${rets.join(', ')} = ${regName(arg1)}(${args_.join(', ')})  -- CALL`;
          break;
        }
        case 'TAILCALL': {
          const nargs_ = (arg2 || 1) - 1;
          const args__ = Array.from({length: nargs_}, (_, i) => regName(arg1 + 1 + i));
          line = `return ${regName(arg1)}(${args__.join(', ')})  -- TAILCALL`;
          break;
        }
        case 'RETURN': {
          if (!arg1 && !arg2) { line = 'return  -- RETURN'; break; }
          const nvals = (arg2 || 1) - 1;
          const vals  = Array.from({length: Math.max(1, nvals)}, (_, i) => regName((arg1||0) + i));
          line = `return ${vals.join(', ')}  -- RETURN`;
          break;
        }
        case 'FORPREP': line = `${regName(arg1)} = ${regName(arg1)} - ${regName(arg1+2)}  -- FORPREP`; indentLevel++; break;
        case 'FORLOOP': line = `${regName(arg1)} = ${regName(arg1)} + ${regName(arg1+2)}; if ${regName(arg1)} <= ${regName(arg1+1)} then goto lbl_${ip+1+(arg2||0)} end  -- FORLOOP`; indentLevel=Math.max(0,indentLevel-1); break;
        case 'CLOSURE': line = `local ${regName(arg1)} = function() --[[closure ${arg2}]] end  -- CLOSURE`; break;
        case 'SETLIST': line = `-- SETLIST ${regName(arg1)}[...]  (#${arg3})`;  break;
        case 'VARARG':  {
          const nva = (arg2 || 1) - 1;
          const vas = Array.from({length: Math.max(1,nva)}, (_, i) => regName((arg1||0)+i));
          line = `${vas.join(', ')} = ...  -- VARARG`;
          break;
        }
        default: line = `-- [ip=${ip}] ${opName}(${[arg1,arg2,arg3].filter(v=>v!==null).join(', ')})`;
      }

      lines.push(`${indent()}${line}`);
      prevIp.val = ip;
    }
  }

  lines.push('-- ══ End of Decompilation ══');
  const pseudoCode = lines.join('\n');

  // #53: decompiled.lua として保存
  let savedPath = null;
  try {
    savedPath = path.join(tempDir, `decompiled_${Date.now()}.lua`);
    fs.writeFileSync(savedPath, pseudoCode, 'utf8');
  } catch {}

  return {
    success: true,
    pseudoCode,
    instructionCount: vmTrace.length,
    blockCount: blocks.length,
    savedPath,
    method: 'vm_decompile',
  };
}

// 後方互換: reconstructedLuaBuilder → vmDecompiler に委譲
function reconstructedLuaBuilder(vmTrace, bytecodeDump, opcodeMap) {
  return vmDecompiler(vmTrace, bytecodeDump, opcodeMap);
}

// ────────────────────────────────────────────────────────────────────────
//  #49/#50  bytecodeテーブル抽出
// ────────────────────────────────────────────────────────────────────────
function parseBytecodeDump(stdout) {
  const bytecodeDump = {};
  for (const line of stdout.split('\n')) {
    const t = line.trim();
    if (!t.startsWith('__BYTECODE__')) continue;
    const parts = t.split('\t');
    if (parts.length < 4) continue;
    const tblName = parts[1], idx = parseInt(parts[2]), val = parseInt(parts[3]);
    if (!bytecodeDump[tblName]) bytecodeDump[tblName] = [];
    bytecodeDump[tblName][idx - 1] = val;
  }
  return bytecodeDump;
}

function vmBytecodeExtractor(code) {
  const tables = [];
  const tblPattern = /local\s+(\w+)\s*=\s*\{((?:\s*\d+\s*,){10,}[^}]*)\}/g;
  let m;
  while ((m = tblPattern.exec(code)) !== null) {
    const name = m[1];
    const nums = m[2].split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
    if (nums.length >= 10) {
      const max = Math.max(...nums);
      tables.push({ name, count: nums.length, sample: nums.slice(0,16), isLikelyBytecode: max < 65536 });
    }
  }
  if (tables.length === 0) return { success: false, error: 'バイトコードテーブルなし', method: 'vm_extract' };
  return {
    success: true, tables, method: 'vm_extract',
    hints: tables.map(t=>`${t.name}[${t.count}]: [${t.sample.join(',')}...]${t.isLikelyBytecode?' (bytecode候補)':''}`),
  };
}

const VM_TRACE_THRESHOLD = 50;
function checkWereDevDetected(vmTrace) { return vmTrace.length >= VM_TRACE_THRESHOLD; }

function dumpBytecodeTables(code) {
  const candidates = [];
  const tblPat = /local\s+(\w+)\s*=\s*\{([\s\d,]+)\}/g;
  let m;
  while ((m = tblPat.exec(code)) !== null) {
    const nums = m[2].split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
    if (nums.length >= 50) candidates.push({ name: m[1], count: nums.length });
  }
  if (candidates.length === 0) return { code, injected: false, candidates: [] };
  let inject = '\n-- ══ YAJU Bytecode Dump ══\n';
  for (const c of candidates) {
    inject += `if type(${c.name})=="table" then\n  for __i,__v in ipairs(${c.name}) do\n    print("__BYTECODE__\\t${c.name}\\t"..tostring(__i).."\\t"..tostring(__v))\n  end\nend\n`;
  }
  return { code: code + inject, injected: true, candidates };
}

// ────────────────────────────────────────────────────────────────────────
//  #55  beautifyLua — 最終コード整形
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
function recursiveDeobfuscate(code, maxDepth, pool) {
  maxDepth=maxDepth||8;
  pool=pool||new CapturePool();
  const seenHashes=new Set();

  // 静的パスのリスト（処理順: #1の要件に対応）
  const staticPasses=[
    { name:'ConstantFolding',    fn: c=>evaluateExpressions(c) },
    { name:'EvalExpressions',    fn: c=>evaluateExpressions(c) },
    { name:'SplitStrings',       fn: c=>deobfuscateSplitStrings(c) },
    { name:'XOR',                fn: c=>xorDecoder(c) },
    { name:'ConstantArray',      fn: c=>constantArrayResolver(c) },
    { name:'CharDecoder',        fn: c=>charDecoder(c) },
    { name:'MathEval',           fn: c=>mathEvaluator(c) },
    { name:'ConstantCall',       fn: c=>constantCallEvaluator(c) },
    { name:'StringTransform',    fn: c=>stringTransformDecoder(c) },
    { name:'DeadBranch',         fn: c=>deadBranchRemover(c) },
    { name:'JunkClean',          fn: c=>junkAssignmentCleaner(c) },
  ];

  let current=code;
  let depth=0;
  const allSteps=[];

  while(depth++<maxDepth){
    const h=cacheHash(current);
    if(seenHashes.has(h)) break;
    seenHashes.add(h);

    // キャッシュチェック
    const cached=cacheGet(current);
    if(cached){ current=cached; allSteps.push({step:'CacheHit',success:true,method:'cache'}); break; }

    let anyChange=false;
    for(const pass of staticPasses){
      const res=pass.fn(current);
      if(res.success&&res.result&&res.result!==current){
        allSteps.push({ step:pass.name, success:true, method:res.method });
        pool.add(res.result, pass.name);
        current=res.result;
        anyChange=true;
      }
    }

    // base64チェック
    base64Detector(current, pool);

    if(!anyChange) break;
  }

  // キャッシュに保存
  if(current!==code) cacheSet(code, current);

  return { code:current, steps:allSteps, pool };
}

// ════════════════════════════════════════════════════════════════════════
//  advancedStaticDeobfuscate  — 全パス統合エントリーポイント
// ════════════════════════════════════════════════════════════════════════
function advancedStaticDeobfuscate(code) {
  const pool=new CapturePool();
  const { code:result, steps } = recursiveDeobfuscate(code, 8, pool);
  const changed=result!==code;
  return {
    success: changed,
    result,
    steps: steps.map(s=>s.step),
    method: 'advanced_static',
    error: changed?undefined:'静的解析で変化なし（動的実行が必要な可能性があります）',
  };
}

// deepStaticDeobfuscate (後方互換)
function deepStaticDeobfuscate(code, maxDepth) {
  const { code:result, steps } = recursiveDeobfuscate(code, maxDepth||6, new CapturePool());
  return { code:result, changed:result!==code };
}

// symbolicExecute, SymbolicEnv (後方互換エクスポート用スタブ)
function symbolicExecute(code, env, depth, visited) {
  const res=recursiveDeobfuscate(code, 2, new CapturePool());
  return { code:res.code, env:env||new SymbolicEnv(), changed:res.code!==code };
}





// ════════════════════════════════════════════════════════
//  AUTO  — v3 解析パイプライン
//
//  処理順 (#1要件):
//   1. advanced_static (ConstantFolding / SymExec / 全静的パス)
//   2. evaluate_expressions
//   3. split_strings
//   4. xor
//   5. constant_array
//   6. dynamic (Lua実行 → 多段ループ)
//   7. vmify (VM検出ヒント)
// ════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════
//  autoDeobfuscate  v4  — 全10項目対応パイプライン
//
//  処理順:
//   ① dynamicDecode (loadstring hook, safeEnv, __DECODED__ dump) ← #1/#2 最初に配置
//   ② loaderPatternDetected チェック → true なら VM解析スキップ   ← #7/#8
//   ③ 静的解析群 (advanced_static, eval, split, xor, constantArray)
//   ④ VM検出 → dynamicDecode結果に対してのみ実行                  ← #1/#5
//   ⑤ VM解析 (vmTraceAnalyzer, reconstructedLuaBuilder)
//   ⑥ #10: decode結果がLuaコードなら再帰パイプライン実行
// ════════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════════
//  BLOCK 4: dynamicDecode v2 + autoDeobfuscate v5 (#1-#57 統合)
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
//  dynamicDecode v2  (#2/#4-#11/#23-#25)
// ────────────────────────────────────────────────────────────────────────
async function dynamicDecode(code) {
  const luaBin = checkLuaAvailable();
  if (!luaBin) return { success: false, error: 'Luaがインストールされていません', method: 'dynamic_decode' };

  const filtered = sandboxFilter(code);
  if (!filtered.safe) return { success: false, error: filtered.reason, method: 'dynamic_decode' };
  if (filtered.removed.length > 0) console.log('[DynDec] 危険関数除去:', filtered.removed.join(', '));

  // preamble: safeEnv + hookLoadstring + vmHookBootstrap
  const preamble = safeEnvPreamble + '\n' + hookLoadstringCode + '\n' + vmHookBootstrap;

  // #23: vmDetector(codeToRun) — hook注入後のコードに対して検出
  let codeToRun = filtered.code;
  let vmHookInjected = false, bytecodeCandidates = [];

  const vmInfoPre = vmDetector(codeToRun);  // hook前の初期検出

  // VM検出後に hook注入
  if (vmInfoPre.isVm || vmInfoPre.isWereDev || vmInfoPre.isMoonSec || vmInfoPre.isLuraph) {
    // #24: /while\s+true\s+do|repeat\s+until/ に拡張
    const hasVmLoop = /while\s+true\s+do|repeat\s+until/.test(codeToRun);
    if (hasVmLoop) {
      const hookResult = injectVmHook(codeToRun, vmInfoPre);
      codeToRun = hookResult.code;
      vmHookInjected = hookResult.injected;
    }
    const dumpResult = dumpBytecodeTables(codeToRun);
    codeToRun = dumpResult.code;
    bytecodeCandidates = dumpResult.candidates;
  }

  // #23: hook注入後のコードで再検出
  const vmInfo = vmDetector(codeToRun);

  const fullCode = preamble + '\n' + codeToRun + '\n' + vmDumpFooter;
  const safeFullCode = fullCode.replace(/\]\]/g, ']] ');
  const tempFile = path.join(tempDir, `dyndec_${Date.now()}_${Math.random().toString(36).substring(7)}.lua`);

  const wrapper = `
-- ══ YAJU dynamicDecode v3 Wrapper ══
-- アンチダンプ・アンチデバッグを無効化
pcall(function()
  if debug then
    debug.sethook=function() end; debug.getinfo=nil
    debug.getlocal=nil; debug.setlocal=nil
    debug.getupvalue=nil; debug.setupvalue=nil
  end
end)
pcall(function()
  if getfenv then
    local env=getfenv()
    env.saveinstance=nil; env.dumpstring=nil; env.save_instance=nil
  end
end)

local __obf_code = [[
${safeFullCode}
]]

-- [1] preamble 内のフックが確実に有効になるよう
-- wrapper レベルでも loadstring / load を直接上書き
local __orig_ls_outer = loadstring or load
local function __outer_hook(c, ...)
  if type(c) == "string" and #c > 10 then
    io.write("\\n__DECODED_START_0__\\n")
    io.write(c)
    io.write("\\n__DECODED_END_0__\\n")
    io.flush()
  end
  return __orig_ls_outer(c, ...)
end
loadstring = __outer_hook
load       = __outer_hook
if rawset then
  pcall(function() rawset(_G, "loadstring", __outer_hook) end)
  pcall(function() rawset(_G, "load",       __outer_hook) end)
end

local __ok, __err = pcall(function()
  local chunk, err = __orig_ls_outer(__obf_code)
  if not chunk then error("parse error: " .. tostring(err)) end
  chunk()
end)

if not __ok then
  io.write("\\n__EXEC_ERROR__:" .. tostring(__err) .. "\\n")
end
`;

  return new Promise(resolve => {
    fs.writeFileSync(tempFile, wrapper, 'utf8');

    // #25: タイムアウト 3000ms
    exec(`${luaBin} ${tempFile}`, { timeout: 3000, maxBuffer: 50 * 1024 * 1024 }, (error, stdout, stderr) => {
      try { fs.unlinkSync(tempFile); } catch {}

      // __DECODED__ 抽出
      const decoded = parseDecodedOutputs(stdout);

      // 旧 __VMLOG__ 形式のトレース（互換）
      const vmTrace      = parseVmLogs(stdout);
      // [4] 新 __VMTRACE__ 形式のトレース（WereDev カスタム VM 対応）
      const vmTraceNew   = parseVmTrace(stdout);
      // [1] string.char / table.concat キャプチャ (VM bytecode 取得)
      const strCharLog   = parseStrCharLog(stdout);
      const tConcatLog   = parseTConcatLog(stdout);
      const bytecodeDump = parseBytecodeDump(stdout);

      // vmTrace を統合（新形式を優先、なければ旧形式）
      const traceForAnalysis = vmTraceNew.found
        ? vmTraceNew.entries.map(e => ({ ip: e.ip || 0, op: e.op, arg1: e.a, arg2: e.b, arg3: e.c }))
        : vmTrace;

      const wereDevDetected = checkWereDevDetected(traceForAnalysis);

      // vmトレースをJSONで保存
      if (traceForAnalysis.length > 0) saveVmTrace(traceForAnalysis, Date.now());

      const vmAnalysis = {
        vmTrace: traceForAnalysis,
        vmTraceRaw:  vmTraceNew.found  ? vmTraceNew  : null,
        strCharLog:  strCharLog.found  ? strCharLog  : null,  // [1]
        tConcatLog:  tConcatLog.found  ? tConcatLog  : null,  // [1]
        bytecodeDump,
        wereDevDetected,
        vmHookInjected,
        bytecodeCandidates,
        vmInfo,
        traceCount: vmTraceNew.found ? vmTraceNew.count : vmTrace.length,
      };
      if (wereDevDetected) {
        vmAnalysis.traceAnalysis  = vmTraceAnalyzer(traceForAnalysis);
        vmAnalysis.reconstruction = vmDecompiler(
          traceForAnalysis, bytecodeDump, vmAnalysis.traceAnalysis.opcodeMap
        );
      }

      // __DECODED__ が取れた場合 [8] captured が短すぎる場合は success にしない
      if (decoded.best && decoded.best.length >= 10) {
        return resolve({
          success: true,
          result: decoded.best,
          allDecoded: decoded.all.map(d => d.code),
          decodedCount: decoded.all.length,
          method: 'dynamic_decode',
          vmAnalysis: vmTrace.length > 0 ? vmAnalysis : undefined,
        });
      }

      // VMトレース再構築が取れた場合
      if (wereDevDetected && vmAnalysis.reconstruction && vmAnalysis.reconstruction.success) {
        const pseudoCode = vmAnalysis.reconstruction.pseudoCode || '';
        // [8] pseudoCode も短すぎる場合は success にしない
        if (pseudoCode.length >= 10) {
          return resolve({
            success: true,
            result: pseudoCode,
            method: 'dynamic_decode_vm',
            vmAnalysis,
            WereDevVMDetected: true,
          });
        }
      }

      // [5] __EXEC_ERROR__ の安全な抽出 (indexOf で存在チェック)
      let errMsg = '';
      if (stdout && stdout.indexOf('__EXEC_ERROR__:') !== -1) {
        const errStart = stdout.indexOf('__EXEC_ERROR__:') + '__EXEC_ERROR__:'.length;
        const errEnd   = stdout.indexOf('\n', errStart);
        errMsg = (errEnd !== -1 ? stdout.substring(errStart, errEnd) : stdout.substring(errStart)).substring(0, 300);
      } else if (stderr) {
        errMsg = stderr.substring(0, 300);
      }

      resolve({
        success: false,
        error: errMsg || 'loadstringが呼ばれませんでした',
        method: 'dynamic_decode',
        vmAnalysis: vmTrace.length > 0 ? vmAnalysis : undefined,
      });
    });
  });
}

async function tryDynamicExecution(code) {
  const luaBin = checkLuaAvailable();
  if (!luaBin) return { success: false, error: 'Luaがインストールされていません', method: 'dynamic' };

  const tempFile = path.join(tempDir, `obf_${Date.now()}_${Math.random().toString(36).substring(7)}.lua`);

  // ]] が含まれる場合のエスケープ
  const safeCode = code.replace(/\]\]/g, '] ]');

  const wrapper = `
-- ══════════════════════════════════════════
--  YAJU Deobfuscator - Dynamic Execution Wrapper
-- ══════════════════════════════════════════

-- 全キャプチャを格納するテーブル（多段対応）
local __captures = {}
local __capture_count = 0
local __original_loadstring = loadstring or load
local __original_load = load or loadstring

-- アンチダンプ・アンチデバッグを無効化
pcall(function()
  if debug then
    debug.sethook = function() end
    debug.getinfo = nil
    debug.getlocal = nil
    debug.setlocal = nil
    debug.getupvalue = nil
    debug.setupvalue = nil
  end
end)
pcall(function()
  if getfenv then
    local env = getfenv()
    env.saveinstance = nil
    env.dumpstring = nil
    env.save_instance = nil
  end
end)

-- loadstring / load を完全フック
local function __hook(code_str, ...)
  if type(code_str) == "string" and #code_str > 20 then
    __capture_count = __capture_count + 1
    __captures[__capture_count] = code_str
  end
  return __original_loadstring(code_str, ...)
end

_G.loadstring = __hook
_G.load       = __hook
if rawset then
  pcall(function() rawset(_G, "loadstring", __hook) end)
  pcall(function() rawset(_G, "load", __hook) end)
end

-- 難読化コードを実行
local __obf_code = [[
${safeCode}
]]

local __ok, __err = pcall(function()
  local chunk, err = __original_loadstring(__obf_code)
  if not chunk then error("parse error: " .. tostring(err)) end
  chunk()
end)

-- キャプチャ結果を出力（最後にキャプチャされたものが最も解読されたもの）
if __capture_count > 0 then
  -- 最も長い（＝最も展開された）コードを選択
  local best = __captures[1]
  for i = 2, __capture_count do
    if #__captures[i] > #best then best = __captures[i] end
  end
  io.write("__CAPTURED_START__")
  io.write(best)
  io.write("__CAPTURED_END__")
  -- 多段情報も出力
  if __capture_count > 1 then
    io.write("__LAYERS__:" .. tostring(__capture_count))
  end
else
  io.write("__NO_CAPTURE__")
  if not __ok then
    io.write("__ERROR__:" .. tostring(__err))
  end
end
`;

  return new Promise(resolve => {
    fs.writeFileSync(tempFile, wrapper, 'utf8');

    exec(`${luaBin} ${tempFile}`, { timeout: 20000, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      try { fs.unlinkSync(tempFile); } catch {}

      // キャプチャ成功
      if (stdout.includes('__CAPTURED_START__') && stdout.includes('__CAPTURED_END__')) {
        const start    = stdout.indexOf('__CAPTURED_START__') + '__CAPTURED_START__'.length;
        const end      = stdout.indexOf('__CAPTURED_END__');
        const captured = stdout.substring(start, end).trim();

        if (captured && captured.length > 5) {
          // [4] captured が元コードとほぼ同じ（長さ差5%以内）なら新レイヤーと判断しない
          const originalLen = code.length;
          const capturedLen = captured.length;
          const diffRatio = Math.abs(capturedLen - originalLen) / Math.max(originalLen, 1);
          if (diffRatio <= 0.05 && captured === code.trim()) {
            return resolve({ success: false, error: 'captured が元コードと同一のため停止', method: 'dynamic' });
          }
          const layerMatch = stdout.match(/__LAYERS__:(\d+)/);
          const layers = layerMatch ? parseInt(layerMatch[1]) : 1;
          return resolve({ success: true, result: captured, layers, method: 'dynamic' });
        }
      }

      // エラー情報
      if (stdout.includes('__ERROR__:')) {
        const errMsg = stdout.split('__ERROR__:')[1] || '';
        return resolve({ success: false, error: 'Luaエラー: ' + errMsg.substring(0, 300), method: 'dynamic' });
      }

      if (error && stderr) {
        return resolve({ success: false, error: '実行エラー: ' + stderr.substring(0, 300), method: 'dynamic' });
      }

      resolve({ success: false, error: 'loadstring()が呼ばれませんでした（VM系難読化の可能性）', method: 'dynamic' });
    });
  });
}

// ────────────────────────────────────────────────────────────────────────
//  autoDeobfuscate v5  (#1-#20, #56/#57 最終処理)
// ────────────────────────────────────────────────────────────────────────
async function autoDeobfuscate(code) {
  const results = [];
  let current = code;
  const luaBin = checkLuaAvailable();

  // ① メイン: 動的実行
  if (luaBin) {
    const dynRes = await tryDynamicExecution(current);
    results.push({ step: '動的実行 (1回目)', ...dynRes });

    if (dynRes.success && dynRes.result) {
      current = dynRes.result;

      // ② 多段難読化対応: 結果をさらに動的実行（最大3回）
      for (let round = 2; round <= 4; round++) {
        // 結果がまだ難読化されていそうか確認（loadstringやBase64の特徴があるか）
        const stillObfuscated = /loadstring|load\s*\(|[A-Za-z0-9+/]{60,}={0,2}/.test(current);
        if (!stillObfuscated) break;

        const dynRes2 = await tryDynamicExecution(current);
        results.push({ step: `動的実行 (${round}回目)`, ...dynRes2 });
        if (dynRes2.success && dynRes2.result && dynRes2.result !== current) {
          current = dynRes2.result;
        } else {
          break; // これ以上変化しないので停止
        }
      }
    } else {
      // ③ 動的実行が失敗 → 静的解析で前処理してから再挑戦
      results.push({ step: '静的解析フォールバック開始', success: true, result: current, method: 'info' });

      const staticSteps = [
        { name: 'SplitStrings',    fn: deobfuscateSplitStrings },
        { name: 'EncryptStrings',  fn: deobfuscateEncryptStrings },
        { name: 'EvalExpressions', fn: evaluateExpressions },
        { name: 'ConstantArray',   fn: deobfuscateConstantArray },
        { name: 'XOR',             fn: deobfuscateXOR },
      ];

      let staticChanged = false;
      for (const step of staticSteps) {
        const res = step.fn(current);
        results.push({ step: step.name, ...res });
        if (res.success && res.result && res.result !== current) {
          current = res.result;
          staticChanged = true;
        }
      }

      // ④ 静的解析で変化があれば動的実行を再試行
      if (staticChanged) {
        const dynRes3 = await tryDynamicExecution(current);
        results.push({ step: '動的実行 (静的解析後)', ...dynRes3 });
        if (dynRes3.success && dynRes3.result) current = dynRes3.result;
      }
    }
  } else {
    // Luaなし → 静的解析のみ
    results.push({ step: '動的実行', success: false, error: 'Luaがインストールされていません', method: 'dynamic' });
    const staticSteps = [
      { name: 'SplitStrings',    fn: deobfuscateSplitStrings },
      { name: 'EncryptStrings',  fn: deobfuscateEncryptStrings },
      { name: 'EvalExpressions', fn: evaluateExpressions },
      { name: 'ConstantArray',   fn: deobfuscateConstantArray },
      { name: 'XOR',             fn: deobfuscateXOR },
      { name: 'Vmify',           fn: deobfuscateVmify },
    ];
    for (const step of staticSteps) {
      const res = step.fn(current);
      results.push({ step: step.name, ...res });
      if (res.success && res.result && res.result !== current) current = res.result;
    }
  }

  return { success: results.some(r => r.success), steps: results, finalCode: current };
}



// ════════════════════════════════════════════════════════
//  Prometheus 難読化
// ════════════════════════════════════════════════════════
function obfuscateWithPrometheus(code, options = {}) {
  return new Promise(resolve => {
    // PrometheusはLua5.1専用 → lua5.1 → luajit → lua の順で探す
    const luaBin = checkLua51Available();
    if (!luaBin) { resolve({ success: false, error: 'lua5.1またはLuaJITがインストールされていません' }); return; }

    const cliPath = fs.existsSync(path.join(__dirname, 'prometheus', 'cli.lua'))
      ? path.join(__dirname, 'prometheus', 'cli.lua')
      : path.join(__dirname, 'cli.lua');

    if (!fs.existsSync(cliPath)) {
      resolve({ success: false, error: 'Prometheusが見つかりません' });
      return;
    }

    const tmpIn  = path.join(tempDir, `prom_in_${crypto.randomBytes(8).toString('hex')}.lua`);
    const tmpOut = path.join(tempDir, `prom_out_${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(tmpIn, code);

    const preset = options.preset || 'Medium';
    // stepsは現状Prometheusのargとして渡すと問題が起きるため使わない
    // preset のみで制御する
    const cmd = `${luaBin} ${cliPath} --preset ${preset} ${tmpIn} --out ${tmpOut}`;

    console.log('[Prometheus] cmd:', cmd);
    console.log('[Prometheus] input preview:', JSON.stringify(code.substring(0, 120)));

    exec(cmd, { timeout: 30000, cwd: path.dirname(cliPath) }, (err, stdout, stderr) => {
      try { fs.unlinkSync(tmpIn); } catch {}
      const errText = (stderr || '').trim();
      const outText = (stdout || '').trim();
      console.log('[Prometheus] stdout:', outText.substring(0, 200));
      console.log('[Prometheus] stderr:', errText.substring(0, 200));
      try {
        if (err) {
          // エラー内容をそのままフロントに返す
          resolve({ success: false, error: 'Lua: ' + errText });
          return;
        }
        if (!fs.existsSync(tmpOut)) {
          resolve({ success: false, error: 'Prometheusが出力ファイルを生成しませんでした。stderr: ' + errText });
          return;
        }
        const result = fs.readFileSync(tmpOut, 'utf8');
        if (!result || result.trim().length === 0) {
          resolve({ success: false, error: 'Prometheusの出力が空でした' });
          return;
        }
        resolve({ success: true, result, preset });
      } finally {
        try { fs.unlinkSync(tmpOut); } catch {}
      }
    });
  });
}

// ════════════════════════════════════════════════════════
//  古い一時ファイルのクリーンアップ
// ════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════
//  カスタムVM難読化
//  Renderサーバー上のLuaで実行される独自VMを生成する
//
//  フロー:
//   1. 入力Luaコードをサーバーに送る
//   2. vm_obfuscator.luaがコードをVM命令列に変換
//      - luacが使える場合: バイトコード → XOR暗号化 → VMランタイム
//      - luacがない場合: ソース → 加算暗号化 → VMランタイム
//   3. 生成されたVMコード（独自インタープリタ付き）を返す
// ════════════════════════════════════════════════════════
function obfuscateWithCustomVM(code, options = {}) {
  return new Promise(resolve => {
    const luaBin = checkLuaAvailable();
    if (!luaBin) {
      resolve({ success: false, error: 'Luaがインストールされていません' });
      return;
    }

    // vm_obfuscator.lua の場所を確認
    const vmScript = path.join(__dirname, 'vm_obfuscator.lua');
    if (!fs.existsSync(vmScript)) {
      resolve({ success: false, error: 'vm_obfuscator.luaが見つかりません' });
      return;
    }

    const seed = options.seed || (Math.floor(Math.random() * 900000) + 100000);
    const tmpIn  = path.join(tempDir, `vm_in_${crypto.randomBytes(8).toString('hex')}.lua`);
    const tmpOut = path.join(tempDir, `vm_out_${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(tmpIn, code, 'utf8');

    const cmd = `${luaBin} ${vmScript} ${tmpIn} --out ${tmpOut} --seed ${seed}`;
    console.log('[VM] cmd:', cmd);

    exec(cmd, { timeout: 30000, cwd: __dirname }, (err, stdout, stderr) => {
      try { fs.unlinkSync(tmpIn); } catch {}

      const outText = (stdout || '').trim();
      const errText = (stderr || '').trim();
      console.log('[VM] stdout:', outText.substring(0, 200));
      if (errText) console.log('[VM] stderr:', errText.substring(0, 200));

      if (err) {
        resolve({ success: false, error: 'VM難読化エラー: ' + (errText || err.message) });
        return;
      }

      // vm_obfuscator.lua は成功時 "OK:<outfile>" を stdout に出力する
      if (!outText.startsWith('OK:') && !fs.existsSync(tmpOut)) {
        resolve({ success: false, error: 'VM難読化失敗: ' + (errText || outText || '出力なし') });
        return;
      }

      try {
        if (!fs.existsSync(tmpOut)) {
          resolve({ success: false, error: '出力ファイルが見つかりません' });
          return;
        }
        const result = fs.readFileSync(tmpOut, 'utf8');
        if (!result || result.trim().length === 0) {
          resolve({ success: false, error: 'VM難読化の出力が空でした' });
          return;
        }
        resolve({ success: true, result, seed, method: 'custom_vm' });
      } finally {
        try { fs.unlinkSync(tmpOut); } catch {}
      }
    });
  });
}

setInterval(() => {
  const now = Date.now();
  fs.readdir(tempDir, (err, files) => {
    if (err) return;
    files.forEach(file => {
      const fp = path.join(tempDir, file);
      fs.stat(fp, (err, stats) => {
        if (!err && now - stats.mtimeMs > 10 * 60 * 1000) fs.unlink(fp, () => {});
      });
    });
  });
}, 5 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`🔥 Lua Obfuscator/Deobfuscator Server running on port ${PORT}`);
  console.log(`   Lua:        ${checkLuaAvailable() || 'NOT FOUND'}`);
  console.log(`   Prometheus: ${checkPrometheusAvailable() ? 'OK' : 'NOT FOUND (optional)'}`);
});
