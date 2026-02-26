--[[
  YAJU Custom VM Obfuscator
  Lua 5.1 / 5.4 両対応 (goto不使用)

  フロー:
    1. 入力Luaコードをソース文字列として読み込む
    2. PRNGキーで加算暗号化 (mod 256)
    3. VMランタイム（独自インタープリタ）と暗号化データを出力
    4. 実行時: VMがキーを再生成 → 復号 → load(コード)()

  引数: lua vm_obfuscator.lua <input.lua> --out <output.lua> [--seed <number>]
]]

-- ── ユーティリティ ──────────────────────────────────────

local function die(msg)
  io.stderr:write("VM_OBF_ERROR: " .. tostring(msg) .. "\n")
  os.exit(1)
end

-- 引数パース
local args = {...}
local input_file  = nil
local output_file = nil
local seed        = math.random(100000, 999999)

local i = 1
while i <= #args do
  if args[i] == "--out" and args[i+1] then
    i = i + 1; output_file = args[i]
  elseif args[i] == "--seed" and args[i+1] then
    i = i + 1; seed = tonumber(args[i]) or seed
  elseif not input_file then
    input_file = args[i]
  end
  i = i + 1
end

if not input_file then
  die("使い方: lua vm_obfuscator.lua input.lua --out output.lua [--seed N]")
end
if not output_file then
  output_file = input_file:gsub("%.lua$", "") .. "_vm.lua"
end

-- ── 入力ファイル読み込み ─────────────────────────────────

local f_in = io.open(input_file, "r")
if not f_in then die("ファイルが開けません: " .. input_file) end
local source_code = f_in:read("*a")
f_in:close()

if not source_code or #source_code == 0 then
  die("入力ファイルが空です: " .. input_file)
end

-- 構文チェック (Lua 5.1: loadstring, Lua 5.2+: load)
local _load = loadstring or load
local chunk, parse_err = _load(source_code)
if not chunk then
  die("Lua構文エラー: " .. tostring(parse_err))
end

-- ── PRNG (線形合同法、Lua 5.1互換) ─────────────────────

local function make_prng(s)
  local state = s
  return function()
    state = (state * 1664525 + 1013904223) % 4294967296
    return state % 256
  end
end

-- ── バイト列を数値テーブルリテラルに変換 ─────────────────

local function bytes_to_table_str(t)
  local lines = {}
  local row   = {}
  for idx = 1, #t do
    row[#row+1] = tostring(t[idx])
    if #row >= 24 then
      lines[#lines+1] = table.concat(row, ",")
      row = {}
    end
  end
  if #row > 0 then lines[#lines+1] = table.concat(row, ",") end
  return "{" .. table.concat(lines, ",\n") .. "}"
end

-- ── ソースコードを暗号化 ─────────────────────────────────
-- 加算 mod 256 (bit32不要、Lua 5.1でも動く)
-- 復号: (enc[i] - key + 256) % 256

local prng_enc = make_prng(seed)
local enc_bytes = {}

for idx = 1, #source_code do
  local b = source_code:byte(idx)
  local k = prng_enc()
  enc_bytes[idx] = (b + k) % 256
end

local enc_table_str = bytes_to_table_str(enc_bytes)

-- ── ランダム変数名生成 (シードベース、衝突回避) ───────────

local function make_vargen(s)
  local prng = make_prng(s + 777)
  local chars = "abcdefghijklmnopqrstuvwxyz"
  local used  = {}
  return function(prefix)
    local name
    local tries = 0
    repeat
      tries = tries + 1
      name = (prefix or "v") .. "_"
      for _ = 1, 8 do
        local ci = prng() % #chars + 1
        name = name .. chars:sub(ci, ci)
      end
    until not used[name] or tries > 50
    used[name] = true
    return name
  end
end

local vargen = make_vargen(seed)

local vData  = vargen("d")  -- 暗号化データテーブル
local vSeed  = vargen("s")  -- PRNGシード
local vPrng  = vargen("p")  -- PRNG関数
local vDec   = vargen("r")  -- 復号バッファ
local vIdx   = vargen("i")  -- ループインデックス
local vKey   = vargen("k")  -- 復号キー
local vOut   = vargen("o")  -- 出力文字列
local vLoad  = vargen("l")  -- load/loadstring参照

-- ── VMランタイムコード生成 ────────────────────────────────
--
--  生成されるコードの構造:
--
--    local d = { 暗号化バイト列 }
--    local s = <seed>
--    local p = function()
--      s = (s*1664525+1013904223)%4294967296
--      return s%256
--    end
--    local r = {}
--    for i = 1, #d do
--      local k = p()
--      r[i] = string.char((d[i] - k + 256) % 256)
--    end
--    local o = table.concat(r)
--    local l = load or loadstring
--    l(o)()

local vm_runtime = string.format(
  "-- [YAJU CustomVM seed=%d]\n"
  .. "local %s=%s\n"
  .. "local %s=%d\n"
  .. "local %s=function()\n"
  .. "  %s=(%s*1664525+1013904223)%%4294967296\n"
  .. "  return %s%%256\n"
  .. "end\n"
  .. "local %s={}\n"
  .. "for %s=1,#%s do\n"
  .. "  local %s=%s()\n"
  .. "  %s[%s]=string.char((%s[%s]-%s+256)%%256)\n"
  .. "end\n"
  .. "local %s=table.concat(%s)\n"
  .. "local %s=load or loadstring\n"
  .. "%s(%s)()",
  -- seed comment
  seed,
  -- local d = {enc_bytes}
  vData, enc_table_str,
  -- local s = seed
  vSeed, seed,
  -- local p = function() s=...; return s%256 end
  vPrng,
    vSeed, vSeed,
    vSeed,
  -- local r = {}
  vDec,
  -- for i = 1, #d do
  vIdx, vData,
    -- local k = p()
    vKey, vPrng,
    -- r[i] = string.char((d[i]-k+256)%256)
    vDec, vIdx, vData, vIdx, vKey,
  -- local o = table.concat(r)
  vOut, vDec,
  -- local l = load or loadstring
  vLoad,
  -- l(o)()
  vLoad, vOut
)

-- ── 出力 ─────────────────────────────────────────────────

local f_out = io.open(output_file, "w")
if not f_out then die("出力ファイルを開けません: " .. output_file) end
f_out:write(vm_runtime)
f_out:close()

-- 成功を stdout に出力（server.js が "OK:" で判定する）
io.write("OK:" .. output_file)
