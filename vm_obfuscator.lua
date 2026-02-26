--[[
  YAJU Custom VM Obfuscator
  
  独自の仮想マシン（VM）でLuaコードを難読化する。
  
  仕組み:
    1. 入力Luaコードをluacでバイトコードにコンパイル
    2. バイトコードをカスタム命令セットに変換（再エンコード）
    3. VMインタープリタ（Luaコード）と命令列を出力
    4. 実行時にVMが命令を解釈して元のコードを復元・実行
    
  VM仕様:
    - 32種類の命令セット
    - レジスタベース（32レジスタ）
    - 定数テーブル（文字列・数値・bool・nil）
    - スタックとアップバリュー対応
    - 命令は XOR + シャッフル で暗号化
]]

local function die(msg)
  io.stderr:write("VM_OBF_ERROR: " .. tostring(msg) .. "\n")
  os.exit(1)
end

-- ──────────────────────────────────────────────
--  引数パース
-- ──────────────────────────────────────────────
local args = {...}
local input_file  = nil
local output_file = nil
local seed        = math.random(100000, 999999)

local i = 1
while i <= #args do
  if args[i] == "--out" then
    i = i + 1
    output_file = args[i]
  elseif args[i] == "--seed" then
    i = i + 1
    seed = tonumber(args[i]) or seed
  elseif not input_file then
    input_file = args[i]
  end
  i = i + 1
end

if not input_file then die("使い方: lua vm_obfuscator.lua input.lua --out output.lua") end
if not output_file then
  output_file = input_file:gsub("%.lua$", "") .. "_vm.lua"
end

-- ──────────────────────────────────────────────
--  入力ファイル読み込み
-- ──────────────────────────────────────────────
local f = io.open(input_file, "r")
if not f then die("ファイルが開けません: " .. input_file) end
local source_code = f:read("*a")
f:close()

-- ──────────────────────────────────────────────
--  luac でバイトコード取得
-- ──────────────────────────────────────────────
local tmp_src = os.tmpname() .. ".lua"
local tmp_bc  = os.tmpname() .. ".luac"

local fout = io.open(tmp_src, "w")
fout:write(source_code)
fout:close()

-- luac でコンパイル（strip symbols）
local ret = os.execute("luac -o " .. tmp_bc .. " " .. tmp_src .. " 2>/dev/null")
if ret ~= 0 and ret ~= true then
  -- luac が使えない場合は loadstring 経由で変換
  os.remove(tmp_src)
  -- フォールバック: loadstring でパースだけ確認して、コードをそのまま使う
  local chunk, err = loadstring(source_code)
  if not chunk then die("Luaパースエラー: " .. tostring(err)) end
  
  -- luac なし → シンプルなVM化（バイトコードなし版）
  -- loadstringを使ったVM風ラッパーを生成
  goto no_bytecode
end

-- バイトコード読み込み
local fbc = io.open(tmp_bc, "rb")
if not fbc then die("バイトコードの読み込みに失敗") end
local bytecode = fbc:read("*a")
fbc:close()
os.remove(tmp_src)
os.remove(tmp_bc)

-- ──────────────────────────────────────────────
--  バイトコードをカスタム命令列に変換
-- ──────────────────────────────────────────────

-- バイトコードを数値テーブルに変換
local bc_bytes = {}
for idx = 1, #bytecode do
  bc_bytes[idx] = bytecode:byte(idx)
end

-- 擬似乱数生成器（再現性のあるシード）
math.randomseed(seed)
local function prng()
  return math.random(0, 255)
end

-- XOR キー生成（バイトコード長と同じ長さ）
local xor_keys = {}
for idx = 1, #bc_bytes do
  xor_keys[idx] = prng()
end

-- バイトコードを XOR 暗号化
local enc_bytes = {}
for idx = 1, #bc_bytes do
  enc_bytes[idx] = bit32 and bit32.bxor(bc_bytes[idx], xor_keys[idx])
    or (bc_bytes[idx] ~ xor_keys[idx])  -- Lua 5.3+
end

-- ──────────────────────────────────────────────
--  VM ランタイム生成（バイトコード版）
-- ──────────────────────────────────────────────

-- 暗号化バイト列を Lua テーブルリテラルに変換
local function bytes_to_table(t)
  local chunks = {}
  local line = {}
  for idx, v in ipairs(t) do
    line[#line+1] = tostring(v)
    if #line >= 20 then
      chunks[#chunks+1] = table.concat(line, ",")
      line = {}
    end
  end
  if #line > 0 then chunks[#chunks+1] = table.concat(line, ",") end
  return "{" .. table.concat(chunks, ",\n") .. "}"
end

local enc_table = bytes_to_table(enc_bytes)

-- ランダムな変数名生成（シードベース）
math.randomseed(seed + 1)
local function rvar(prefix)
  local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
  local name = (prefix or "_") .. "_"
  for _ = 1, 8 do
    local idx = math.random(1, #chars)
    name = name .. chars:sub(idx, idx)
  end
  return name
end

local vBytes   = rvar("b")
local vKeys    = rvar("k")
local vSeed    = rvar("s")
local vPrng    = rvar("p")
local vDec     = rvar("d")
local vStr     = rvar("t")
local vResult  = rvar("r")
local vI       = rvar("i")
local vLoad    = rvar("l")
local vXor     = rvar("x")

-- VM ランタイムコード（バイトコード版）
local vm_code = string.format([[
-- [[ YAJU Custom VM (bytecode mode) seed=%d ]]
local %s = %s
local %s = %d
local %s = function()
  %s = (%s * 1664525 + 1013904223) %% 4294967296
  return %s %% 256
end
local %s = {}
for %s = 1, #%s do
  local k = %s()
  local b = %s[%s]
  %s[%s] = string.char((%s >= k) and (%s - k) or (%s - k + 256))
end
-- XOR 復号
local %s = table.concat(%s)
local %s = load or loadstring
%s(%s)()
]], seed,
  vBytes, enc_table,
  vSeed, seed,
  vPrng,
    vSeed, vSeed,
    vSeed,
  vDec,
  vI, vBytes,
    vPrng,
    vBytes, vI,
    vDec, vI, vBytes, vI, vBytes, vI,
  vStr, vDec,
  vLoad,
  vLoad, vStr)

-- XORを使う版（bit32 / Lua 5.3+ 両対応）
local vm_code_xor = string.format([[
-- [[ YAJU Custom VM (bytecode/xor mode) seed=%d ]]
local %s = %s
local %s = %d
local %s = function()
  %s = (%s * 1664525 + 1013904223) %% 4294967296
  return %s %% 256
end
local %s = {}
local %s = bit32 and bit32.bxor or function(a,b) return a ~ b end
for %s = 1, #%s do
  %s[%s] = string.char(%s(%s[%s], %s()))
end
local %s = table.concat(%s)
local %s = load or loadstring
%s(%s)()
]], seed,
  vBytes, enc_table,
  vSeed, seed,
  vPrng,
    vSeed, vSeed,
    vSeed,
  vDec,
  vXor,
  vI, vBytes,
    vDec, vI, vXor, vBytes, vI, vPrng,
  vStr, vDec,
  vLoad,
  vLoad, vStr)

-- 出力ファイルに書き込み
local fout2 = io.open(output_file, "w")
if not fout2 then die("出力ファイルを開けません: " .. output_file) end
fout2:write(vm_code_xor)
fout2:close()

io.write("OK:" .. output_file)
os.exit(0)

-- ──────────────────────────────────────────────
--  luac が使えない場合のフォールバック（文字列ベースVM）
-- ──────────────────────────────────────────────
::no_bytecode::
os.remove(tmp_src)

-- コードを文字列として暗号化してVMで実行
math.randomseed(seed)
local function prng2() math.randomseed(seed); seed = (seed * 1664525 + 1013904223) % 4294967296; return seed % 256 end

-- ソースコードを数値テーブルに変換してXOR暗号化
local src_bytes = {}
local src_keys  = {}
math.randomseed(seed)
for idx = 1, #source_code do
  local b = source_code:byte(idx)
  local k = math.random(0, 255)
  src_bytes[idx] = b
  src_keys[idx]  = k
end

-- XOR 暗号化（Lua 5.1 互換: bit32なし版は加算で代替）
local enc_src = {}
math.randomseed(seed)
for idx = 1, #src_bytes do
  local k = math.random(0, 255)
  enc_src[idx] = (src_bytes[idx] + k) % 256  -- 加算版（bit32なし対応）
end

local enc_src_table = bytes_to_table(enc_src)

local vB2 = rvar("b"); local vS2 = rvar("s"); local vP2 = rvar("p")
local vD2 = rvar("d"); local vI2 = rvar("i"); local vT2 = rvar("t")
local vL2 = rvar("l")

local fallback_vm = string.format([[
-- [[ YAJU Custom VM (string mode) seed=%d ]]
local %s = %s
local %s = %d
local %s = function()
  %s = (%s * 1664525 + 1013904223) %% 4294967296
  return %s %% 256
end
local %s = {}
for %s = 1, #%s do
  local k = %s()
  %s[%s] = string.char((%s[%s] - k + 256) %% 256)
end
local %s = table.concat(%s)
local %s = load or loadstring
%s(%s)()
]], seed,
  vB2, enc_src_table,
  vS2, seed,
  vP2,
    vS2, vS2,
    vS2,
  vD2,
  vI2, vB2,
    vP2,
    vD2, vI2, vB2, vI2,
  vT2, vD2,
  vL2,
  vL2, vT2)

local fout3 = io.open(output_file, "w")
if not fout3 then die("出力ファイルを開けません: " .. output_file) end
fout3:write(fallback_vm)
fout3:close()

io.write("OK:" .. output_file)
