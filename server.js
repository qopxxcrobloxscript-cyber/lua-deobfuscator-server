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

const tempDir = path.join(__dirname, 'temp');
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir);

function checkLuaAvailable() {
  try { execSync('lua -v 2>&1', { timeout: 3000 }); return 'lua'; } catch {}
  try { execSync('luajit -v 2>&1', { timeout: 3000 }); return 'luajit'; } catch {}
  return null;
}

function checkLua51Available() {
  try { execSync('lua5.1 -v 2>&1', { timeout: 3000 }); return 'lua5.1'; } catch {}
  try { execSync('luajit -v 2>&1', { timeout: 3000 }); return 'luajit'; } catch {}
  try { execSync('lua -v 2>&1', { timeout: 3000 }); return 'lua'; } catch {}
  return null;
}

function checkPrometheusAvailable() {
  return fs.existsSync(path.join(__dirname, 'prometheus', 'cli.lua'))
      || fs.existsSync(path.join(__dirname, 'cli.lua'));
}

app.get('/api/status', (req, res) => {
  res.json({
    status: 'ok',
    lua: checkLuaAvailable() || 'not installed',
    prometheus: checkPrometheusAvailable() ? 'available' : 'not found',
    deobfuscateMethods: ['auto', 'xor', 'split_strings', 'encrypt_strings', 'constant_array', 'vmify', 'dynamic'],
    obfuscatePresets:   ['Minify', 'Weak', 'Medium', 'Strong'],
    obfuscateSteps:     ['SplitStrings', 'EncryptStrings', 'ConstantArray', 'ProxifyLocals', 'WrapInFunction', 'Vmify'],
  });
});

app.post('/api/deobfuscate', async (req, res) => {
  const { code, method } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });

  let result;
  switch (method) {
    case 'xor':             result = deobfuscateXOR(code);            break;
    case 'split_strings':   result = deobfuscateSplitStrings(code);   break;
    case 'encrypt_strings': result = deobfuscateEncryptStrings(code);  break;
    case 'constant_array':  result = deobfuscateConstantArray(code);   break;
    case 'eval_expressions':result = evaluateExpressions(code);        break;
    case 'vmify':           result = deobfuscateVmify(code);           break;
    case 'dynamic':         result = await tryDynamicExecution(code);  break;
    case 'auto':
    default:                result = await autoDeobfuscate(code);      break;
  }

  res.json(result);
});

app.post('/deobfuscate', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(deobfuscateXOR(code));
});

app.post('/api/obfuscate', async (req, res) => {
  const { code, preset, steps } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(await obfuscateWithPrometheus(code, { preset, steps }));
});

app.post('/api/vm-obfuscate', async (req, res) => {
  const { code, seed } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(await obfuscateWithCustomVM(code, { seed }));
});

// ════════════════════════════════════════════════════════
//  動的実行 (全面強化版)
//
//  強化点:
//   1. Roblox依存関数を全てスタブ化 (task.wait, coroutine等)
//   2. string.charフックで数値配列からの文字列生成を捕捉
//   3. loadstring/loadを多重フック (rawset + metatable)
//   4. アンチデバッグを徹底的に無効化
//   5. VM opcodeループ対策: pcallでタイムアウト付き実行
//   6. 全キャプチャから最長・最高スコアのものを選択
//   7. 多段実行: 最大5ラウンド
// ════════════════════════════════════════════════════════
async function tryDynamicExecution(code) {
  const luaBin = checkLuaAvailable();
  if (!luaBin) return { success: false, error: 'Luaがインストールされていません', method: 'dynamic' };

  const tempFile = path.join(tempDir, `obf_${Date.now()}_${Math.random().toString(36).substring(7)}.lua`);
  const codeB64  = Buffer.from(code, 'utf8').toString('base64');

  const wrapper = `
-- ══════════════════════════════════════════════════════════════
--  YAJU Full-Trace Deobfuscator v4
--
--  設計方針:
--   1. loadstring/load フックで「渡された文字列」を全て記録
--   2. キャプチャしたコードをさらに再帰実行 (最大15段)
--   3. string.char / table.concat フックで数値配列→文字列も補足
--   4. VM型: while+opcode ループが loadstring を呼ぶまで追跡
--   5. 最終段階 (最後にキャプチャされたコード) を出力
-- ══════════════════════════════════════════════════════════════

-- ── Base64デコーダ ───────────────────────────────────────────
local function b64decode(s)
  local alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
  local map = {}
  for i = 1, #alpha do map[string.byte(alpha,i,i)] = i-1 end
  local out, p = {}, 1
  for i = 1, #s, 4 do
    local a = map[string.byte(s,i,i)]
    local b = map[string.byte(s,i+1,i+1)]
    local c = map[string.byte(s,i+2,i+2)]
    local d = map[string.byte(s,i+3,i+3)]
    if not a or not b then break end
    out[p]=string.char((a*4+math.floor(b/16))%256); p=p+1
    if not c then break end
    out[p]=string.char(((b%16)*16+math.floor(c/4))%256); p=p+1
    if not d then break end
    out[p]=string.char(((c%4)*64+d)%256); p=p+1
  end
  return table.concat(out)
end

local __obf_code = b64decode("${codeB64}")

-- ── ログ ─────────────────────────────────────────────────────
-- stage_log[i] = { code, source, depth }
-- 順番が重要: 最後の要素が最終段階
local stage_log  = {}
local str_log    = {}   -- string.char/table.concat で生成された文字列
local __running  = false

-- ── Luaコードスコア ──────────────────────────────────────────
local function lua_score(s)
  if not s or #s < 4 then return 0 end
  local score = 0
  for _, kw in ipairs({"local","function","end","if","then","return",
                        "for","do","while","loadstring","load","require",
                        "pcall","string","table","math","print"}) do
    local _, n = s:gsub("%f[%a]"..kw.."%f[%A]","")
    score = score + n * 8
  end
  local sample = math.min(#s, 2000)
  local pr = 0
  for i = 1, sample do
    local c = s:byte(i)
    if c >= 32 and c <= 126 then pr = pr + 1 end
  end
  return score + (pr / sample) * 80
end

-- ── スタブオブジェクト ────────────────────────────────────────
local function stub()
  return setmetatable({},{
    __index    = function(t,k) return stub() end,
    __newindex = function() end,
    __call     = function(...) return stub() end,
    __tostring = function() return "" end,
    __len      = function() return 0 end,
  })
end

-- ── Roblox/エクスプロイト環境スタブ ─────────────────────────
local stubs = {
  wait=function()end, spawn=function(f,...)pcall(f,...)end,
  delay=function(t,f,...)pcall(f,...)end,
  getgenv=function()return _G end, getrenv=function()return _G end,
  getsenv=function()return _G end,
  hookfunction=function(f)return f end,
  newcclosure=function(f)return f end,
  iscclosure=function()return false end,
  islclosure=function()return true end,
  checkcaller=function()return false end,
  isexecutorclosure=function()return false end,
  saveinstance=function()end, dumpstring=function()end,
  readfile=function()return""end, writefile=function()end,
  appendfile=function()end, listfiles=function()return{}end,
  getrawmetatable=function(t)return getmetatable(t)end,
  setrawmetatable=function(t,m)return setmetatable(t,m)end,
  rconsoleprint=function()end, rconsolewarn=function()end,
  rconsoleerr=function()end,
  printidentity=function()end,
  identifyexecutor=function()return"",2 end,
  getexecutorname=function()return""end,
  game=stub(), workspace=stub(), script=stub(),
  Instance={new=function()return stub()end},
  Vector3={new=function(x,y,z)return{x=x or 0,y=y or 0,z=z or 0}end},
  CFrame={new=function(...)return stub()end,fromEulerAnglesXYZ=function(...)return stub()end},
  Color3={new=function(...)return{}end,fromRGB=function(...)return{}end},
  UDim2={new=function(...)return{}end},
  Enum=setmetatable({},{__index=function(t,k)return setmetatable({},{__index=function(t2,k2)return k2 end})end}),
  Players={LocalPlayer={Character=nil,UserId=0,Name="Player",GetMouse=function()return stub()end}},
  RunService={
    Heartbeat={Connect=function()return{Disconnect=function()end}end,Wait=function()return 0 end},
    RenderStepped={Connect=function()return{Disconnect=function()end}end,Wait=function()return 0 end},
    Stepped={Connect=function()return{Disconnect=function()end}end,Wait=function()return 0 end},
    IsStudio=function()return false end,
  },
  UserInputService=stub(), TweenService={Create=function()return{Play=function()end}end},
  HttpService={JSONDecode=function()return{}end,JSONEncode=function()return"{}"end},
  task={wait=function()end,spawn=function(f,...)pcall(f,...)end,
        defer=function(f,...)pcall(f,...)end,delay=function(t,f,...)pcall(f,...)end,cancel=function()end},
}
for k,v in pairs(stubs) do rawset(_G,k,v) end

-- ── アンチデバッグ無効化 ─────────────────────────────────────
pcall(function()
  if debug then
    debug.sethook=function()end
    debug.getinfo=function()return{}end
    debug.getlocal=function()return nil end
    debug.setlocal=function()end
    debug.getupvalue=function()return nil end
    debug.setupvalue=function()end
    debug.traceback=function()return""end
  end
end)

-- ── 原本の関数を保存 ────────────────────────────────────────
local __orig_ls      = loadstring or load
local __orig_ld      = load or loadstring
local __orig_strchar = string.char
local __orig_concat  = table.concat
local __orig_pcall   = pcall
local __orig_xpcall  = xpcall

-- ── 多段トレース実行エンジン ─────────────────────────────────
-- depth: 現在の再帰深度
-- seen:  既に実行したコードのハッシュ集合 (無限ループ防止)
local MAX_DEPTH   = 15
local MAX_INSTR   = 6000000
local seen_codes  = {}

local function simple_hash(s)
  local h = 0
  local step = math.max(1, math.floor(#s / 64))
  for i = 1, #s, step do
    h = (h * 31 + s:byte(i)) % 1000000007
  end
  return h .. "_" .. #s
end

-- 前方宣言
local trace_execute

-- loadstring/load フック生成
local function make_ls_hook(depth)
  return function(code_str, chunkname, ...)
    local chunk, err
    if type(code_str) == "string" and #code_str > 8 then
      -- ログに記録
      local sc = lua_score(code_str)
      stage_log[#stage_log+1] = { code=code_str, source="loadstring", depth=depth, score=sc }

      -- コンパイル
      chunk, err = __orig_ls(code_str, chunkname, ...)

      -- 次段階を非同期に追跡 (再帰実行)
      if chunk and depth < MAX_DEPTH then
        local hash = simple_hash(code_str)
        if not seen_codes[hash] then
          seen_codes[hash] = true
          trace_execute(code_str, depth + 1)
        end
      end
    else
      chunk, err = __orig_ls(code_str, chunkname, ...)
    end
    return chunk, err
  end
end

-- string.charフック: 数値配列→文字列を補足
string.char = function(...)
  local r = __orig_strchar(...)
  if #r >= 6 then
    local sc = lua_score(r)
    if sc >= 20 then
      str_log[#str_log+1] = { code=r, source="string.char", score=sc }
    end
  end
  return r
end

-- table.concatフック: VM文字列結合を補足
table.concat = function(t, sep, i, j)
  local r = __orig_concat(t, sep, i, j)
  if type(r)=="string" and #r >= 6 then
    local sc = lua_score(r)
    if sc >= 20 then
      str_log[#str_log+1] = { code=r, source="table.concat", score=sc }
      -- table.concatで生成された高スコアコードを即座にトレース
      if sc >= 50 and #stage_log == 0 then
        local hash = simple_hash(r)
        if not seen_codes[hash] then
          seen_codes[hash] = true
          local chunk = __orig_ls(r)
          if chunk then
            -- フックを仕込んで実行
            rawset(_G,"loadstring",make_ls_hook(1))
            rawset(_G,"load",make_ls_hook(1))
            pcall(chunk)
          end
        end
      end
    end
  end
  return r
end

-- トレース実行本体
trace_execute = function(code_str, depth)
  if depth > MAX_DEPTH then return end
  local hash = simple_hash(code_str)
  if seen_codes[hash] then return end
  seen_codes[hash] = true

  -- このdepth用のフックをセット
  local ls_hook = make_ls_hook(depth)
  rawset(_G, "loadstring", ls_hook)
  rawset(_G, "load",       ls_hook)
  pcall(function()
    local mt = getmetatable(_G) or {}
    mt.__index = function(t,k)
      if k=="loadstring" or k=="load" then return ls_hook end
      return rawget(t,k)
    end
    setmetatable(_G, mt)
  end)

  -- 命令数制限
  local instr = 0
  pcall(function()
    if debug and debug.sethook then
      debug.sethook(function()
        instr = instr + 1
        if instr > MAX_INSTR then error("__LIMIT__") end
      end,"",500)
    end
  end)

  local chunk, err = __orig_ls(code_str)
  if chunk then
    pcall(chunk)
  end

  pcall(function()
    if debug and debug.sethook then debug.sethook() end
  end)
end

-- ── メイン実行 ───────────────────────────────────────────────
-- まず depth=0 でトレース実行
trace_execute(__obf_code, 0)

-- ── 結果選択 ────────────────────────────────────────────────
-- 優先順位:
--   1. stage_log の最後のエントリ (最終loadstring段階)
--   2. stage_log 中でスコア最高のもの
--   3. str_log 中でスコア最高のもの

local function pick_best(log_table)
  -- 最後のloadstringキャプチャを優先
  for i = #log_table, 1, -1 do
    local e = log_table[i]
    if e.source == "loadstring" and #e.code > 10 then
      return e
    end
  end
  -- なければスコア最高
  local best, best_sc = nil, -1
  for _, e in ipairs(log_table) do
    if (e.score or 0) > best_sc then
      best_sc = e.score
      best = e
    end
  end
  return best
end

local result = pick_best(stage_log)

-- stage_logが空ならstr_logから探す
if not result then
  result = pick_best(str_log)
end

-- ── 出力 ────────────────────────────────────────────────────
if result and #result.code > 5 then
  io.write("__CAPTURED_START__")
  io.write(result.code)
  io.write("__CAPTURED_END__")
  io.write(string.format("__META__stages=%d,source=%s,score=%d,depth=%d",
    #stage_log,
    tostring(result.source),
    math.floor(result.score or 0),
    result.depth or 0))
else
  io.write("__NO_CAPTURE__")
end
`;

  return new Promise(resolve => {
    fs.writeFileSync(tempFile, wrapper, 'utf8');

    exec(`${luaBin} ${tempFile}`, { timeout: 35000, maxBuffer: 20 * 1024 * 1024 }, (error, stdout, stderr) => {
      try { fs.unlinkSync(tempFile); } catch {}

      if (stdout.includes('__CAPTURED_START__') && stdout.includes('__CAPTURED_END__')) {
        const s   = stdout.indexOf('__CAPTURED_START__') + '__CAPTURED_START__'.length;
        const e   = stdout.indexOf('__CAPTURED_END__');
        const captured = stdout.substring(s, e);

        const meta    = stdout.substring(e + '__CAPTURED_END__'.length);
        const stagesM = meta.match(/stages=(\d+)/);
        const sourceM = meta.match(/source=([^,]+)/);
        const scoreM  = meta.match(/score=(\d+)/);
        const depthM  = meta.match(/depth=(\d+)/);

        if (captured && captured.length > 5) {
          return resolve({
            success: true,
            result:  captured,
            stages:  stagesM ? parseInt(stagesM[1]) : 1,
            source:  sourceM ? sourceM[1] : 'unknown',
            score:   scoreM  ? parseInt(scoreM[1])  : 0,
            depth:   depthM  ? parseInt(depthM[1])  : 0,
            method:  'dynamic',
          });
        }
      }

      if (stdout.includes('__NO_CAPTURE__')) {
        return resolve({ success: false, error: '完全なVM型難読化のため動的解読不可（opcodeエミュレーションが必要）', method: 'dynamic' });
      }
      if (error && stderr) {
        return resolve({ success: false, error: 'プロセスエラー: ' + stderr.substring(0, 300), method: 'dynamic' });
      }

      resolve({ success: false, error: 'コードが生成されませんでした', method: 'dynamic' });
    });
  });
}


// ════════════════════════════════════════════════════════
//  静的解読メソッド群
// ════════════════════════════════════════════════════════

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
        cur += content.substring(i, end + 2);
        i = end + 2; continue;
      }
      else if (c === '{') { depth++; cur += c; }
      else if (c === '}') { depth--; cur += c; }
      else if (c === ',' && depth === 0) { elements.push(cur.trim()); cur = ''; }
      else { cur += c; }
    } else {
      if (c === '\\') { cur += c + (content[i+1] || ''); i += 2; continue; }
      if (c === strChar) { inStr = false; }
      cur += c;
    }
    i++;
  }
  if (cur.trim()) elements.push(cur.trim());
  return elements;
}

function resolveLuaStringEscapes(str) {
  return str
    .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\r/g, '\r')
    .replace(/\\\\/g, '\\').replace(/\\"/g, '"').replace(/\\'/g, "'")
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\(\d{1,3})/g, (_, d) => String.fromCharCode(parseInt(d, 10)));
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

function xorDecryptByte(byte, key) {
  let result = 0;
  for (let i = 0; i < 8; i++) {
    const a = (byte >> i) & 1, b = (key >> i) & 1;
    if (a !== b) result |= (1 << i);
  }
  return result;
}

function deobfuscateXOR(code) {
  const patterns = [/local\s+\w+\s*=\s*\{([0-9,\s]+)\}/g, /\{([0-9,\s]+)\}/g];
  let encryptedArrays = [];
  for (const pattern of patterns) {
    let match;
    const p = new RegExp(pattern.source, pattern.flags);
    while ((match = p.exec(code)) !== null) {
      const nums = match[1].split(',').map(n => parseInt(n.trim())).filter(n => !isNaN(n));
      if (nums.length > 3) encryptedArrays.push(nums);
    }
    if (encryptedArrays.length > 0) break;
  }
  if (encryptedArrays.length === 0) return { success: false, error: '暗号化配列が見つかりません', method: 'xor' };
  let bestResult = null, bestScore = -1, bestKey = -1;
  for (const arr of encryptedArrays) {
    for (let key = 0; key <= 255; key++) {
      const str = arr.map(b => String.fromCharCode(xorDecryptByte(b, key))).join('');
      const score = scoreLuaCode(str);
      if (score > bestScore) { bestScore = score; bestResult = str; bestKey = key; }
    }
  }
  if (bestScore < 10) return { success: false, error: '有効なLuaコードが見つかりませんでした', method: 'xor' };
  return { success: true, result: bestResult, key: bestKey, score: bestScore, method: 'xor' };
}

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

function deobfuscateConstantArray(code) {
  let modified = code, found = false;
  let passCount = 0;
  while (passCount++ < 10) {
    let changed = false;
    const arrayPattern = /local\s+(\w+)\s*=\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g;
    let match;
    const snapshot = modified;
    while ((match = arrayPattern.exec(snapshot)) !== null) {
      const varName = match[1], content = match[2];
      const elements = parseLuaArrayElements(content);
      if (elements.length < 1) continue;
      const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const indexRe = new RegExp(escaped + '\\[([^\\]]+)\\]', 'g');
      modified = modified.replace(indexRe, (fullMatch, indexExpr) => {
        const idx = evalSimpleExpr(indexExpr.trim());
        if (idx === null || idx < 1 || idx > elements.length) return fullMatch;
        found = true; changed = true;
        return elements[idx - 1];
      });
    }
    if (!changed) break;
  }
  if (!found) return { success: false, error: 'ConstantArrayパターンが見つかりません', method: 'constant_array' };
  return { success: true, result: modified, method: 'constant_array' };
}

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

// ════════════════════════════════════════════════════════
//  AUTO
// ════════════════════════════════════════════════════════
async function autoDeobfuscate(code) {
  const results = [];
  let current = code;
  const luaBin = checkLuaAvailable();

  if (luaBin) {
    const dynRes = await tryDynamicExecution(current);
    results.push({ step: '動的実行 (1回目)', ...dynRes });

    if (dynRes.success && dynRes.result) {
      current = dynRes.result;

      for (let round = 2; round <= 5; round++) {
        const stillObfuscated = /loadstring|load\s*\(|[A-Za-z0-9+/]{60,}={0,2}/.test(current);
        if (!stillObfuscated) break;

        const dynRes2 = await tryDynamicExecution(current);
        results.push({ step: `動的実行 (${round}回目)`, ...dynRes2 });
        if (dynRes2.success && dynRes2.result && dynRes2.result !== current) {
          current = dynRes2.result;
        } else {
          break;
        }
      }
    } else {
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

      if (staticChanged) {
        const dynRes3 = await tryDynamicExecution(current);
        results.push({ step: '動的実行 (静的解析後)', ...dynRes3 });
        if (dynRes3.success && dynRes3.result) current = dynRes3.result;
      }
    }
  } else {
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
    const cmd = `${luaBin} ${cliPath} --preset ${preset} ${tmpIn} --out ${tmpOut}`;

    exec(cmd, { timeout: 30000, cwd: path.dirname(cliPath) }, (err, stdout, stderr) => {
      try { fs.unlinkSync(tmpIn); } catch {}
      const errText = (stderr || '').trim();
      try {
        if (err) { resolve({ success: false, error: 'Lua: ' + errText }); return; }
        if (!fs.existsSync(tmpOut)) { resolve({ success: false, error: 'Prometheusが出力ファイルを生成しませんでした。stderr: ' + errText }); return; }
        const result = fs.readFileSync(tmpOut, 'utf8');
        if (!result || result.trim().length === 0) { resolve({ success: false, error: 'Prometheusの出力が空でした' }); return; }
        resolve({ success: true, result, preset });
      } finally {
        try { fs.unlinkSync(tmpOut); } catch {}
      }
    });
  });
}

// ════════════════════════════════════════════════════════
//  カスタムVM難読化
// ════════════════════════════════════════════════════════
function obfuscateWithCustomVM(code, options = {}) {
  return new Promise(resolve => {
    const luaBin = checkLuaAvailable();
    if (!luaBin) { resolve({ success: false, error: 'Luaがインストールされていません' }); return; }

    const vmScript = path.join(__dirname, 'vm_obfuscator.lua');
    if (!fs.existsSync(vmScript)) { resolve({ success: false, error: 'vm_obfuscator.luaが見つかりません' }); return; }

    const seed = options.seed || (Math.floor(Math.random() * 900000) + 100000);
    const tmpIn  = path.join(tempDir, `vm_in_${crypto.randomBytes(8).toString('hex')}.lua`);
    const tmpOut = path.join(tempDir, `vm_out_${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(tmpIn, code, 'utf8');

    const cmd = `${luaBin} ${vmScript} ${tmpIn} --out ${tmpOut} --seed ${seed}`;

    exec(cmd, { timeout: 30000, cwd: __dirname }, (err, stdout, stderr) => {
      try { fs.unlinkSync(tmpIn); } catch {}

      const outText = (stdout || '').trim();
      const errText = (stderr || '').trim();

      if (err) { resolve({ success: false, error: 'VM難読化エラー: ' + (errText || err.message) }); return; }
      if (!outText.startsWith('OK:') && !fs.existsSync(tmpOut)) { resolve({ success: false, error: 'VM難読化失敗: ' + (errText || outText || '出力なし') }); return; }

      try {
        if (!fs.existsSync(tmpOut)) { resolve({ success: false, error: '出力ファイルが見つかりません' }); return; }
        const result = fs.readFileSync(tmpOut, 'utf8');
        if (!result || result.trim().length === 0) { resolve({ success: false, error: 'VM難読化の出力が空でした' }); return; }
        resolve({ success: true, result, seed, method: 'custom_vm' });
      } finally {
        try { fs.unlinkSync(tmpOut); } catch {}
      }
    });
  });
}

// ════════════════════════════════════════════════════════
//  フル難読化 API  POST /api/full-obfuscate
// ════════════════════════════════════════════════════════
app.post('/api/full-obfuscate', async (req, res) => {
  const { code, seed } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });

  let current = code;

  const vmRes = await obfuscateWithCustomVM(current, { seed });
  if (vmRes.success && vmRes.result) {
    current = vmRes.result;
  } else {
    return res.json({ success: false, error: 'VM難読化失敗: ' + (vmRes.error || '') });
  }

  const XOR_DEPTH = 36;
  const B64_LAYERS = 10;
  const JUNK_COUNT = 250;

  const masterSeed = seed || (Math.floor(Math.random() * 99999999) + 100000);
  let rngState = masterSeed;
  const rng = () => { rngState = (rngState * 1664525 + 1013904223) % 4294967296; return rngState; };

  const ops = [];
  for (let i = 0; i < XOR_DEPTH; i++) {
    const r = rng();
    ops.push({
      type: Math.floor((r % 100) / 34),
      keyBase: Math.floor((r / 256) % 255) + 1,
      prime: [2,3,5,7,11,13,17,19,23,29,31][Math.floor((r % 1000) / 100)] || 3
    });
  }

  let bytes = Buffer.from(current, 'utf8');
  for (let pass = 0; pass < XOR_DEPTH; pass++) {
    const { type: tp, keyBase: k, prime: p } = ops[pass];
    for (let i = 0; i < bytes.length; i++) {
      const dk = (k * (i + p)) % 256;
      if (tp === 0) bytes[i] = bytes[i] ^ dk;
      else if (tp === 1) bytes[i] = (bytes[i] + dk) % 256;
      else bytes[i] = (bytes[i] - dk + 256) % 256;
    }
  }

  let encoded = bytes.toString('base64');
  for (let i = 1; i < B64_LAYERS; i++) {
    encoded = Buffer.from(encoded).toString('base64');
  }

  const usedVars = new Set();
  const makeVar = () => {
    const starts = ['I','l','O','Il','lI','OI','IO','lO','Ol'];
    const chars  = ['I','l','O','_','1','0'];
    let name;
    do {
      name = starts[Math.floor(Math.random() * starts.length)];
      const len = 10 + Math.floor(Math.random() * 8);
      for (let i = 0; i < len; i++) name += chars[Math.floor(Math.random() * chars.length)];
    } while (usedVars.has(name));
    usedVars.add(name);
    return name;
  };

  const numExpr = (n) => {
    const a = Math.floor(Math.random() * 40) + 2;
    const b = Math.floor(n / a);
    const c = n - a * b;
    return `(${a}*${b}+${c})`;
  };

  const makeJunk = (count) => {
    let out = '';
    for (let i = 0; i < count; i++) {
      const r = Math.random();
      const v = makeVar();
      if (r < 0.3) out += `local ${v}=${numExpr(Math.floor(Math.random()*9999)+1)}\n`;
      else if (r < 0.6) out += `local ${v}=function()return ${numExpr(Math.floor(Math.random()*100))} end\n`;
      else out += `local ${v}={${[1,2,3].map(()=>numExpr(Math.floor(Math.random()*100)+1)).join(',')}}\n`;
    }
    return out;
  };

  const vLib  = makeVar(), vStr = makeVar(), vTbl = makeVar();
  const vMap  = makeVar(), vIdx = makeVar(), vS   = makeVar();
  const vRr   = makeVar(), vPp  = makeVar(), vNn  = makeVar();
  const vAa   = makeVar(), vBb  = makeVar(), vCc  = makeVar(), vDd = makeVar();
  const vAlpha= makeVar(), vParts= makeVar();
  const vLd   = makeVar();
  const vXorFn= makeVar(), vXA  = makeVar(), vXB  = makeVar();
  const vXSeed= makeVar(), vXNxt= makeVar(), vXOps= makeVar();
  const vXPrim= makeVar(), vXI  = makeVar(), vXR  = makeVar();
  const vXTp  = makeVar(), vXKb = makeVar(), vXPr = makeVar();
  const vXPass= makeVar(), vXOp = makeVar(), vXDk = makeVar();
  const vXB2  = makeVar(), vXOut= makeVar(), vXVar= makeVar();
  const vVM2  = makeVar(), vVMSt= makeVar();

  const fullAlpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
  const aKey = Math.floor(Math.random() * 40) + 5;
  const chunks = [];
  for (let i = 0; i < fullAlpha.length; i += 11) {
    const chunk = fullAlpha.substring(i, i + 11);
    const enc = chunk.split('').map(c => c.charCodeAt(0) + aKey).join(',');
    chunks.push(`(function()local _t={${enc}};local _r={};for _i=1,#_t do _r[_i]=string.char(_t[_i]-${aKey})end;return table.concat(_r)end)()`);
  }

  const sA = Math.floor(Math.random() * 800) + 100;
  const sB = Math.floor(masterSeed / sA);
  const sC = masterSeed - sA * sB;
  const mulA = Math.floor(Math.random() * 900) + 100;
  const mulB = Math.floor(1664525 / mulA);
  const mulC = 1664525 - mulA * mulB;
  const addA = Math.floor(Math.random() * 900) + 100;
  const addB = Math.floor(1013904223 / addA);
  const addC = 1013904223 - addA * addB;

  const xorDecoder = `
local function ${vXorFn}(${vXA},${vXB})
  local _=0
  for _i=0,7 do
    local _a=math.floor(${vXA}/2^_i)%2
    local _b=math.floor(${vXB}/2^_i)%2
    if _a~=_b then _=_+2^_i end
  end
  return _
end
local function ${vXVar}(${vS})
  local ${vXB2}={}
  for ${vXI}=1,#${vS} do ${vXB2}[${vXI}]=string.byte(${vS},${vXI}) end
  local ${vXSeed}=${sA}*${sB}+${sC}
  local function ${vXNxt}() ${vXSeed}=(${vXSeed}*(${mulA}*${mulB}+${mulC})+${addA}*${addB}+${addC})%(2^32);return ${vXSeed} end
  local ${vXOps}={}
  local ${vXPrim}={2,3,5,7,11,13,17,19,23,29,31}
  for ${vXI}=1,${XOR_DEPTH} do
    local ${vXR}=${vXNxt}()
    local ${vXTp}=math.floor((${vXR}%100)/34)
    local ${vXKb}=math.floor((${vXR}/256)%255)+1
    local ${vXPr}=${vXPrim}[math.floor((${vXR}%1000)/100)+1] or 3
    table.insert(${vXOps},{${vXTp},${vXKb},${vXPr}})
  end
  for ${vXPass}=${XOR_DEPTH},1,-1 do
    local ${vXOp}=${vXOps}[${vXPass}]
    local ${vXTp},${vXKb},${vXPr}=${vXOp}[1],${vXOp}[2],${vXOp}[3]
    for ${vXI}=1,#${vXB2} do
      local ${vXDk}=(${vXKb}*(${vXI}+${vXPr}))%256
      if ${vXTp}==0 then ${vXB2}[${vXI}]=${vXorFn}(${vXB2}[${vXI}],${vXDk})
      elseif ${vXTp}==1 then ${vXB2}[${vXI}]=(${vXB2}[${vXI}]-${vXDk}+256)%256
      elseif ${vXTp}==2 then ${vXB2}[${vXI}]=(${vXB2}[${vXI}]+${vXDk})%256 end
    end
  end
  local ${vXOut}={}
  for ${vXI}=1,#${vXB2} do ${vXOut}[${vXI}]=string.char(${vXB2}[${vXI}]) end
  return table.concat(${vXOut})
end
`;

  const b64Decoder = `
local ${vParts}={${chunks.join(',')}}
local ${vAlpha}=table.concat(${vParts})
local ${vMap}={}
for ${vIdx}=1,#${vAlpha} do ${vMap}[string.byte(${vAlpha},${vIdx},${vIdx})]=${vIdx}-1 end
local function ${vLib}(${vS})
  local ${vRr},${vPp},${vNn}={},1,#${vS}
  for ${vIdx}=1,${vNn},4 do
    local ${vAa},${vBb},${vCc},${vDd}=${vMap}[string.byte(${vS},${vIdx},${vIdx})],${vMap}[string.byte(${vS},${vIdx}+1,${vIdx}+1)],${vMap}[string.byte(${vS},${vIdx}+2,${vIdx}+2)],${vMap}[string.byte(${vS},${vIdx}+3,${vIdx}+3)]
    if not ${vAa} or not ${vBb} then break end
    ${vRr}[${vPp}]=string.char((${vAa}*4+math.floor(${vBb}/16))%256) ${vPp}=${vPp}+1
    if not ${vCc} then break end
    ${vRr}[${vPp}]=string.char(((${vBb}%16)*16+math.floor(${vCc}/4))%256) ${vPp}=${vPp}+1
    if not ${vDd} then break end
    ${vRr}[${vPp}]=string.char(((${vCc}%4)*64+${vDd})%256) ${vPp}=${vPp}+1
  end
  return table.concat(${vRr})
end
`;

  const lsKey = Math.floor(Math.random() * 40) + 5;
  const lsEnc = 'loadstring'.split('').map(c => c.charCodeAt(0) + lsKey).join(',');
  const ldRef = `local ${vLd}=(function()local _t={${lsEnc}};local _r={};for _i=1,#_t do _r[_i]=string.char(_t[_i]-${lsKey})end;return rawget(_G,table.concat(_r)) or loadstring end)()`;

  const steps = [];
  for (let i = 0; i < B64_LAYERS; i++) steps.push(`${vStr}=${vLib}(${vStr})`);
  steps.push(`${vStr}=${vXVar}(${vStr})`);
  steps.push(`local _f,_e=${vLd}(${vStr});if _f then _f() else error(_e) end return`);

  let vmDisp = '{';
  for (let i = 0; i < steps.length; i++) {
    vmDisp += `[${i}]=function()${steps[i]} return ${i === steps.length - 1 ? -1 : i + 1}end,`;
  }
  vmDisp += '}';

  const finalLua = `(function()
${makeJunk(Math.floor(JUNK_COUNT / 5))}
${b64Decoder}
${xorDecoder}
${ldRef}
local ${vStr}="${encoded}"
local ${vVMSt}=0
local ${vVM2}=${vmDisp}
while ${vVMSt}~=-1 do ${vVMSt}=${vVM2}[${vVMSt}]()end
end)()`;

  res.json({ success: true, result: finalLua, seed: masterSeed, method: 'full' });
});

// 古い一時ファイルのクリーンアップ
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
