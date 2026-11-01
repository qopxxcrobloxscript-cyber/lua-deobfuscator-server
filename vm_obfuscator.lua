--[[
  YAJU True VM Obfuscator v4.2
  Lua5.1/エクスプロイト環境対応版
  ビット演算子(&,|,~,<<,>>)をLua5.1互換関数に置き換え
]]

local function die(msg)
  io.stderr:write("VM_OBF_ERROR: " .. tostring(msg) .. "\n")
  os.exit(1)
end

local args = {...}
local input_file, output_file = nil, nil
local seed = math.random(100000, 999999)
local strength = 5 -- カスタムVM強度 (1=軽量 〜 15=最重量, 既定5)
do
  local i = 1
  while i <= #args do
    if args[i]=="--out" and args[i+1] then i=i+1; output_file=args[i]
    elseif args[i]=="--seed" and args[i+1] then i=i+1; seed=tonumber(args[i]) or seed
    elseif args[i]=="--strength" and args[i+1] then i=i+1; strength=tonumber(args[i]) or strength
    elseif not input_file then input_file=args[i]
    end
    i=i+1
  end
end
-- 強度を 1〜15 にクランプ（不正値はデフォルト5相当として扱う）
if type(strength)~="number" then strength=5 end
if strength<1 then strength=1 elseif strength>15 then strength=15 end
if not input_file then die("usage: lua vm_obfuscator.lua input.lua --out out.lua") end
if not output_file then output_file=input_file:gsub("%.lua$","").."_vm.lua" end

local fh = io.open(input_file,"r")
if not fh then die("cannot open: "..input_file) end
local source = fh:read("*a"); fh:close()
if not source or #source==0 then die("empty input") end

local rng_s = seed
-- BUGFIX: LCG(線形合同法)は下位ビットほど統計的な質が悪く、周期が極端に
-- 短くなることが知られている。rng_s をそのまま %N に使うと、Nが2の累乗
-- (例: 8, 16)のときに特定のseedで極端に短い周期に陥り、"同じ名前しか
-- 生成されない"→ repeat-until が無限ループする、という実際の不具合が
-- 発生した(例: --seed 999)。
-- 対策として、下位16bitを捨てて上位ビット側(統計的な質が良い)だけを
-- 返すようにする。rng_sの値域は[0,2^32-1]なので、返り値は[0,65535]と
-- なり、本ファイル内の用途(名前生成・定数分解パターン選択など、
-- 必要な値域はせいぜい数百〜数千)に対して十分な幅を持つ。
local function rng()
  rng_s=(rng_s*1664525+1013904223)%4294967296
  return math.floor(rng_s/65536)
end
-- FINGERPRINT-HARDENING: 変数名の文字構成パターンをビルド(=生成1回)ごとに
-- ランダムで選ぶ。従来は常に I/l/O/_/1/0 のみで構成される固定パターンだった
-- ため、2つの出力を見比べるだけで「同一ツール製」だと即座に特定できて
-- しまっていた。複数の命名スタイルを用意し、--seedごとに1つを選ぶことで、
-- 出力ごとに見た目の異なる命名規則になるようにする。
local NAME_STYLES = {
  -- スタイル1(従来): 紛らわしい大文字I/小文字l/大文字Oだけで構成
  {conf={"I","l","O","Il","lI","IO","OI","lO","Ol"}, fill={"I","l","O","_","1","0"}},
  -- スタイル2: アンダースコア主体、l/O抜き(異なる視覚パターン)
  {conf={"_","__","_v","_x","_k"}, fill={"_","a","b","c","d","e","f"}},
  -- スタイル3: 16進数風(0-9,a-f)の識別子。他ツールの"_0x..."系命名に近い見た目
  {conf={"a","b","c","d","e","f","_a","_b"}, fill={"a","b","c","d","e","f","0","1","2","3","4","5","6","7","8","9"}},
  -- スタイル4: O/0混在+記号多め、l/Iを使わない(スタイル1と対照的な見た目)
  {conf={"O","Q","D","OQ","QD","DO"}, fill={"O","Q","D","_","8","9"}},
}
local nameStyle = NAME_STYLES[(rng()%#NAME_STYLES)+1]
local used_v={}
local function V()
  local conf=nameStyle.conf
  local fill=nameStyle.fill
  local n
  repeat
    n=conf[(rng()%#conf)+1]
    for _=1,8+(rng()%5) do n=n..fill[(rng()%#fill)+1] end
  until not used_v[n]
  used_v[n]=true; return n
end
-- CONST-HARDENING: 整数定数の分解パターンを4種類に増やし、ランダムに
-- 使い分ける。加算型(a*b+c)の形だけだと解析者はその1パターンだけ認識すれば
-- 全ての整数定数を読めてしまうため、減算型(a*b-c)も混在させて形を崩す。
local function ne(n)
  if type(n)~="number" then return tostring(n) end
  if n==0 then return "0" end
  local r=rng()%4
  if r==0 then local a=(rng()%40)+2;local b=math.floor(n/a);local c=n-a*b;return("(%d*%d+%d)"):format(a,b,c)
  elseif r==1 then local o=(rng()%80)+5;return("(%d-%d)"):format(n+o,o)
  elseif r==2 then local f=(rng()%6)+2;local q=math.floor(n/f);local c=n-f*q;return("(%d*%d+%d)"):format(f,q,c)
  else local a=(rng()%30)+2;local b=math.ceil(n/a);local c=a*b-n;return("(%d*%d-%d)"):format(a,b,c) end
end

-- CONST-HARDENING: 浮動小数点定数の保護。
-- 従来は数値定数のうち整数値のみ ne() で分解され、小数(例: 3.14, 0.5)は
-- tostring(c) によってソースにそのまま平文で出力されていた。
-- ここでは %.17g (倍精度を誤差なく文字列化できる精度)で10進表現を取り出し、
-- 「整数部+小数部」を1つの整数Mとみなして ne(M) で分解した上で、
-- 10^E (Eは小数桁数)で割って元の値を再構成する式を生成する。
-- M/10^E が元の%.17g表現と完全に一致するため精度は保たれ、Mの部分は
-- 既存の整数定数保護と同じ強度で保護される。桁数が大きすぎて整数Mが
-- doubleの精度(2^53)を超える場合は、安全側に倒して平文のまま出力する
-- (保護より数値精度の正確さを優先)。
local function obfuscate_float(c)
  local s = string.format("%.17g", c)
  if s:find("[eEnN]") then return s end -- 指数表記/inf/nanは手を出さずそのまま
  local neg = false
  if s:sub(1,1)=="-" then neg=true; s=s:sub(2) end
  local intPart, fracPart = s:match("^(%d*)%.?(%d*)$")
  if not intPart then return (neg and "-" or "")..s end
  intPart = (intPart=="") and "0" or intPart
  local digits = intPart..fracPart
  -- 先頭の余分な0を除去(tonumberで数値化するだけなので実害はないが整形)
  local E = #fracPart
  if #digits > 15 then return (neg and "-" or "")..s end -- 精度境界を超える場合は保護を諦める
  local M = tonumber(digits)
  if not M then return (neg and "-" or "")..s end
  local expr
  if E==0 then
    expr = ne(M)
  else
    local D=1; for _=1,E do D=D*10 end
    expr = ("(%s)/(%s)"):format(ne(M), ne(D))
  end
  if neg then expr = "-("..expr..")" end
  return expr
end

-- HARDENING: 整合性チェック関数を生成する。この関数の戻り値は正常環境では
-- 常に0になり、hide_str()の文字列復号キーに無害に加算される。既知のダンプ/
-- デバッグ/フックAPIが有効なままだったり、明らかに異常な実行タイミングを
-- 検知した場合は非ゼロを返し、以降デコードされる全ての文字列定数(=実際の
-- プログラムの中身)が破損する。これにより、整合性チェックは「取り除いても
-- 実行結果に影響しない安全な副作用コード」ではなくなり、静的解析による
-- 到達不能コード除去・純粋関数除去でも無効化できなくなる(Luraphの
-- 「プリVMがチェックを通してから本体を復号する」設計と同じ考え方)。
local vIntegrityFnName
local integrityFnSource
do
  local fn = V()
  local vG, vGk, vGv, vGh, vAcc = V(), V(), V(), V(), V()
  local vHashFn, vHK, vHi, vHh = V(), V(), V(), V()
  local vHashTbl = V()
  local vD, vHookOk = V(), V()
  local vT1, vT2, vI, vAcc2 = V(), V(), V(), V()

  -- 危険APIのハッシュ値(多項式ハッシュ, +,*,% のみ使用。JS側実装と方式は
  -- 異なるが、ここはLua単体で完結するチェックなので一致させる必要はない)
  local DANGEROUS = {
    "saveinstance","save_instance","dumpstring","decompile","Decompile",
    "getscriptbytecode","getscripthash","getscriptclosure",
    "getscriptfunction","dumpstring_raw","loadstring_dump",
  }
  local HASH_MOD = 2147483647
  local function luaPolyHash(str)
    local h = 5381
    for i=1,#str do h=(h*33+str:byte(i))%HASH_MOD end
    return h
  end
  local hashVals = {}
  for _,name in ipairs(DANGEROUS) do hashVals[#hashVals+1] = luaPolyHash(name) end

  local parts = {}
  parts[#parts+1] = ("local function %s(%s)local %s=5381 for %s=1,#%s do %s=(%s*33+%s:byte(%s))%%%d end return %s end")
    :format(vHashFn, vHK, vHh, vHi, vHK, vHh, vHh, vHK, vHi, HASH_MOD, vHh)
  parts[#parts+1] = ("local %s={%s}"):format(vHashTbl, table.concat(hashVals, ","))
  parts[#parts+1] = ("local function %s()"):format(fn)
  parts[#parts+1] = ("local %s=0"):format(vAcc)
  -- チェック1: _G に既知の危険APIが生きていないか (next()ウォーク、pairs不使用)
  -- pairs(_G) はシグネチャとして解読ツールに検出されるため next() で代替する
  parts[#parts+1] = ("pcall(function() local %s,_gv=next(_G,nil) while %s~=nil do if type(%s)==\"string\" then local %s=%s(%s) local _hi=1 while _hi<=#%s do if %s[_hi]==%s then %s=%s+1 end _hi=_hi+1 end end %s,_gv=next(_G,%s) end end)")
    :format(vGk, vGk, vGk, vGh, vHashFn, vGk, vHashTbl, vHashTbl, vGh, vAcc, vAcc, vGk, vGk)
  -- チェック2: debug.sethook が非nilかつ呼び出し可能な既定外の値になっていないか
  -- rawget経由でアクセスし "debug" 文字列を隠す
  parts[#parts+1] = ("local %s=rawget(_G,(function()local _k={115,100,103,117,98};local _r={}  for _i=1,5 do _r[_i]=string.char(_k[_i]-1) end return table.concat(_r) end)())"):format(vD)
  parts[#parts+1] = ("local %s=0 if type(%s)==\"table\" then local _sh=rawget(%s,\"sethook\") if type(_sh)==\"function\" then pcall(rawset,%s,\"sethook\",function() end) end end")
    :format(vHookOk, vD, vD, vD)
  parts[#parts+1] = ("%s=%s+%s"):format(vAcc, vAcc, vHookOk)
  -- チェック3: 粗いタイミングチェック(過検知を避けるため非常に緩い閾値)
  parts[#parts+1] = ("local %s=os and os.clock and os.clock() or 0"):format(vT1)
  parts[#parts+1] = ("local %s=0 for %s=1,20000 do %s=%s+%s%%7 end"):format(vAcc2, vI, vAcc2, vAcc2, vI)
  parts[#parts+1] = ("local %s=os and os.clock and os.clock() or 0"):format(vT2)
  -- 通常は数ミリ秒以内に終わるはずのループが極端に遅い(=デバッガでステップ
  -- 実行されている等)場合のみ非ゼロを加える。閾値は誤検知を避けるため2秒と
  -- 十分に緩く設定。
  parts[#parts+1] = ("if (%s-%s)>2 then %s=%s+1 end"):format(vT2, vT1, vAcc, vAcc)
  parts[#parts+1] = ("return %s"):format(vAcc)
  parts[#parts+1] = "end"

  vIntegrityFnName = fn
  integrityFnSource = table.concat(parts, "\n")
end

-- ★ FIX: %255+1 方式（値域1..255、\0絶対なし）
-- enc = (byte + key + f(i) - 1) % 255 + 1 → 値域1..255
-- dec = (enc - 1 - key - f(i) + 1020) % 255 + 1 → 値域1..255
-- 入力のLua識別子・文字列リテラルにbyte=0は来ないので情報落ちなし
--
-- STRING-HARDENING: 位置依存項f(i)の形を複数用意し、文字列ごとにランダムで
-- 選ぶ。全ての文字列が同じ1つの復号パターンを使っていると、解析者はその
-- パターンを一度覚えるだけで全ての文字列を一括復号できてしまう。f(i)の
-- 形を(i%7)*3以外にも複数用意しランダムに混在させることで、「1つの復号器」
-- では読めない文字列が混在するようにする。数式は加減算のみで必ず可逆。
local F_VARIANTS = {
  function(i) return (i%7)*3 end,
  function(i) return (i%5)*7+(i%3) end,
  function(i) return (i%11)*2 end,
  function(i) return ((i*3)%13)+(i%4) end,
  function(i) return (i%9)*5-(i%2) end,
}
-- f(i)が取りうる値の絶対上限(全バリアント共通の安全マージンとして使う)。
-- 上記バリアントは最大でも (10*2)=20 程度なので、余裕を持って40とする。
local F_MAXABS = 40

-- STRUCTURE-HARDENING: 文字列を復号するIIFEの「全体構造」も複数用意し、
-- 文字列ごとにランダムで選ぶ。従来はf(i)の数式だけがバリアントで、
-- IIFEの構造(forループ+table+table.concat)自体は常に同一だったため、
-- その構造1つにマッチする正規表現を書くだけで全文字列を機械的に
-- 抽出できてしまっていた(実際に提供された解析レポートで指摘された
-- 弱点)。ループの種類(for/while)や結果の組み立て方(table.concat /
-- 直接文字列連結)を変えた3種の構造を用意し、ランダムに混在させる。
local function buildDecodeBody_ForTable(vt,vr,vi,vick,key,fiExpr,n)
  return ("local %s={};for %s=1,%d do %s[%s]=string.char((%s[%s]-1-%d-(%s)-%s+1020+%d*255)%%255+1)end;return table.concat(%s)")
    :format(vr, vi, n, vr, vi, vt, vi, key, fiExpr, vick, F_MAXABS, vr)
end
local function buildDecodeBody_WhileTable(vt,vr,vi,vick,key,fiExpr,n)
  return ("local %s={};%s=1;while %s<=%d do %s[%s]=string.char((%s[%s]-1-%d-(%s)-%s+1020+%d*255)%%255+1);%s=%s+1 end;return table.concat(%s)")
    :format(vr, vi, vi, n, vr, vi, vt, vi, key, fiExpr, vick, F_MAXABS, vi, vi, vr)
end
local function buildDecodeBody_ForConcat(vt,vr,vi,vick,key,fiExpr,n)
  return ("local %s=\"\";for %s=1,%d do %s=%s..string.char((%s[%s]-1-%d-(%s)-%s+1020+%d*255)%%255+1)end;return %s")
    :format(vr, vi, n, vr, vr, vt, vi, key, fiExpr, vick, F_MAXABS, vr)
end
local DECODE_BODY_BUILDERS = {buildDecodeBody_ForTable, buildDecodeBody_WhileTable, buildDecodeBody_ForConcat}

-- 1個の文字列チャンクをエンコードしたIIFE式(文字列)を返す。
local function encode_chunk(s)
  if #s==0 then return '""' end
  local key=(rng()%50)+3
  local variant=math.random(1,#F_VARIANTS)
  local f=F_VARIANTS[variant]
  local enc={}
  for i=1,#s do
    enc[i]=ne((s:byte(i)+key+f(i)-1)%255+1)
  end
  local vt,vi,vick=V(),V(),V()
  -- f(i)を復号式に埋め込む(variantごとに式テキストを変える)
  local fiExpr
  if variant==1 then fiExpr = ("%s%%7*3"):format(vi)
  elseif variant==2 then fiExpr = ("%s%%5*7+%s%%3"):format(vi,vi)
  elseif variant==3 then fiExpr = ("%s%%11*2"):format(vi)
  elseif variant==4 then fiExpr = ("(%s*3)%%13+%s%%4"):format(vi,vi)
  else fiExpr = ("%s%%9*5-%s%%2"):format(vi,vi)
  end
  -- HARDENING: 復号キーに整合性チェック関数(vIntegrityFnName, 後述で定義)の
  -- 戻り値を加える。正常環境では常に0を返すため通常の復号結果には一切影響
  -- しないが、既知のダンプ/デバッグAPIが有効な状態(=改ざん・解析ツール
  -- 使用中)だと非ゼロを返し、キーがずれて文字列全体が破損する。
  -- これにより、整合性チェックが「副作用のない除去可能なコード」ではなく
  -- 「実際の出力(文字列定数)に影響する必須ロジック」になり、静的解析による
  -- 到達不能/無害コード除去で無効化することができなくなる。
  local vr = V()
  local builder = DECODE_BODY_BUILDERS[math.random(1,#DECODE_BODY_BUILDERS)]
  local body = builder(vt, vr, vi, vick, key, fiExpr, #s)
  return("(function()local %s={%s};local %s=%s();%s end)()"):format(
    vt, table.concat(enc,","), vick, vIntegrityFnName or "(function() return 0 end)", body)
end

-- STRING-HARDENING: 一定長を超える文字列は複数チャンクに分割し、チャンクごとに
-- 別々の鍵・別々の数式バリアントで独立に暗号化してから ".." で連結する。
-- これにより、長い(=意味のある可能性が高い)文字列ほど「1箇所にまとまった
-- 復号処理」を持たなくなり、部分的な解析だけでは全体を読めなくなる。
local CHUNK_THRESHOLD = 24
local function hide_str(s)
  if not s or #s==0 then return '""' end
  if #s <= CHUNK_THRESHOLD then
    return encode_chunk(s)
  end
  -- 2〜4分割(文字列長に応じて分割数を増やす)
  local chunkCount = math.min(4, math.max(2, math.floor(#s / CHUNK_THRESHOLD) + 1))
  local baseLen = math.floor(#s / chunkCount)
  local pieces = {}
  local pos = 1
  for c=1,chunkCount do
    local len = (c==chunkCount) and (#s-pos+1) or baseLen
    local part = s:sub(pos, pos+len-1)
    pieces[#pieces+1] = encode_chunk(part)
    pos = pos + len
  end
  return "("..table.concat(pieces, "..")..")"
end

local TK = {
  NUMBER="NUMBER", STRING="STRING", NAME="NAME", EOF="EOF",
  AND="and",BREAK="break",DO="do",ELSE="else",ELSEIF="elseif",
  END="end",FALSE="false",FOR="for",FUNCTION="function",GOTO="goto",
  IF="if",IN="in",LOCAL="local",NIL="nil",NOT="not",
  OR="or",REPEAT="repeat",RETURN="return",THEN="then",TRUE="true",
  UNTIL="until",WHILE="while",
  PLUS="+",MINUS="-",STAR="*",SLASH="/",PERCENT="%",CARET="^",HASH="#",
  AMP="&",TILDE="~",PIPE="|",LSHIFT="<<",RSHIFT=">>",DSLASH="//",
  EQ="==",NEQ="~=",LT="<",GT=">",LEQ="<=",GEQ=">=",
  ASSIGN="=",LPAREN="(",RPAREN=")",LBRACE="{",RBRACE="}",LBRACKET="[",RBRACKET="]",
  DCOLON="::",SEMI=";",COLON=":",COMMA=",",DOT=".",CONCAT="..",DOTS="...",
  -- Luau/Roblox compound assignment operators (not present in vanilla Lua 5.1,
  -- but extremely common in real-world Luau scripts). Each compiles down to
  -- ordinary SET_LOCAL/SET_GLOBAL/SET_FIELD/SET_TABLE opcodes after desugaring
  -- "lhs OP= rhs" into "lhs = lhs OP rhs" in the parser, so no new VM opcodes
  -- are needed — only new tokens and a parser case.
  PLUSEQ="+=",MINUSEQ="-=",STAREQ="*=",SLASHEQ="/=",
  DSLASHEQ="//=",PERCENTEQ="%=",CARETEQ="^=",CONCATEQ="..=",
}
local KEYWORDS={}
for _,k in ipairs({"and","break","do","else","elseif","end","false","for",
  "function","goto","if","in","local","nil","not","or","repeat","return",
  "then","true","until","while"}) do KEYWORDS[k]=k end

local function Lexer(src)
  local self={src=src, pos=1, line=1, tokens={}, ti=1}
  local function cur() return self.src:sub(self.pos,self.pos) end
  local function peek2() return self.src:sub(self.pos,self.pos+1) end
  local function peek3() return self.src:sub(self.pos,self.pos+2) end
  local function adv(n) n=n or 1; local s=self.src:sub(self.pos,self.pos+n-1); self.pos=self.pos+n; return s end
  local function skipWS()
    while self.pos<=#self.src do
      local c=cur()
      if c==" " or c=="\t" or c=="\r" then adv()
      elseif c=="\n" then adv(); self.line=self.line+1
      elseif peek2()=="--" then
        adv(2)
        if cur()=="[" then
          local lvl=0; local p=self.pos+1
          while self.src:sub(p,p)=="=" do lvl=lvl+1; p=p+1 end
          if self.src:sub(p,p)=="[" then
            self.pos=p+1
            local close="]"..string.rep("=",lvl).."]"
            local e=self.src:find(close,self.pos,true)
            if e then self.pos=e+#close else self.pos=#self.src+1 end
          else
            local e=self.src:find("\n",self.pos,true)
            self.pos=e and e or #self.src+1
          end
        else
          local e=self.src:find("\n",self.pos,true)
          self.pos=e and e or #self.src+1
        end
      else break end
    end
  end
  local function readLongStr()
    local lvl=0
    while cur()=="=" do lvl=lvl+1; adv() end
    if cur()~="[" then return nil end
    adv()
    if cur()=="\n" then adv(); self.line=self.line+1 end
    local close="]"..string.rep("=",lvl).."]"
    local buf={}
    while self.pos<=#self.src do
      if self.src:sub(self.pos,self.pos+#close-1)==close then
        self.pos=self.pos+#close; return table.concat(buf)
      end
      local c=adv()
      if c=="\n" then self.line=self.line+1 end
      buf[#buf+1]=c
    end
    die("unfinished long string at line "..self.line)
  end
  local function readStr(q)
    adv()
    local buf={}
    while self.pos<=#self.src do
      local c=cur()
      if c==q then adv(); return table.concat(buf) end
      if c=="\n" or c=="\r" then die("unfinished string at line "..self.line) end
      if c=="\\" then
        adv(); local e=cur(); adv()
        if e=="n" then buf[#buf+1]="\n"
        elseif e=="t" then buf[#buf+1]="\t"
        elseif e=="r" then buf[#buf+1]="\r"
        elseif e=="\\" then buf[#buf+1]="\\"
        elseif e=="'" then buf[#buf+1]="'"
        elseif e=='"' then buf[#buf+1]='"'
        elseif e=="a" then buf[#buf+1]="\a"
        elseif e=="b" then buf[#buf+1]="\b"
        elseif e=="f" then buf[#buf+1]="\f"
        elseif e=="v" then buf[#buf+1]="\v"
        elseif e=="0" then buf[#buf+1]="\0"
        elseif e=="x" then
          local h=adv(2); buf[#buf+1]=string.char(tonumber(h,16) or 0)
        elseif e>="0" and e<="9" then
          local ds=e
          if cur()>="0" and cur()<="9" then ds=ds..adv() end
          if cur()>="0" and cur()<="9" then ds=ds..adv() end
          buf[#buf+1]=string.char(tonumber(ds) or 0)
        elseif e=="\n" then buf[#buf+1]="\n"; self.line=self.line+1
        else buf[#buf+1]=e end
      else buf[#buf+1]=c; adv() end
    end
    die("unfinished string")
  end
  local function readNum()
    local start=self.pos
    if peek2()=="0x" or peek2()=="0X" then
      adv(2); while cur():match("[0-9a-fA-F_]") do adv() end
    else
      while cur():match("[0-9]") do adv() end
      if cur()=="." and self.src:sub(self.pos+1,self.pos+1):match("[0-9]") then
        adv(); while cur():match("[0-9]") do adv() end
      end
      if cur():match("[eE]") then
        adv()
        if cur():match("[+-]") then adv() end
        while cur():match("[0-9]") do adv() end
      end
    end
    return tonumber((self.src:sub(start,self.pos-1):gsub("_","")))
  end
  function self:tokenize()
    while true do
      skipWS()
      if self.pos>#self.src then self.tokens[#self.tokens+1]={type=TK.EOF,line=self.line}; break end
      local line=self.line
      local c=cur()
      if c:match("[0-9]") or (c=="." and self.src:sub(self.pos+1,self.pos+1):match("[0-9]")) then
        self.tokens[#self.tokens+1]={type=TK.NUMBER,value=readNum(),line=line}
      elseif c=='"' or c=="'" then
        self.tokens[#self.tokens+1]={type=TK.STRING,value=readStr(c),line=line}
      elseif c=="[" and (self.src:sub(self.pos+1,self.pos+1)=="[" or self.src:sub(self.pos+1,self.pos+1)=="=") then
        local sp=self.pos; adv()
        local s=readLongStr()
        if s then self.tokens[#self.tokens+1]={type=TK.STRING,value=s,line=line}
        else self.pos=sp; adv(); self.tokens[#self.tokens+1]={type=TK.LBRACKET,line=line} end
      elseif c:match("[a-zA-Z_]") then
        local s={}
        while cur():match("[a-zA-Z0-9_]") do s[#s+1]=adv() end
        local word=table.concat(s)
        self.tokens[#self.tokens+1]={type=KEYWORDS[word] or TK.NAME, value=word, line=line}
      else
        local p3=peek3(); local p2=peek2()
        if p3=="..." then adv(3); self.tokens[#self.tokens+1]={type=TK.DOTS,line=line}
        elseif p3=="..=" then adv(3); self.tokens[#self.tokens+1]={type=TK.CONCATEQ,line=line}
        elseif p3=="//=" then adv(3); self.tokens[#self.tokens+1]={type=TK.DSLASHEQ,line=line}
        elseif p2==".." then adv(2); self.tokens[#self.tokens+1]={type=TK.CONCAT,line=line}
        elseif p2=="==" then adv(2); self.tokens[#self.tokens+1]={type=TK.EQ,line=line}
        elseif p2=="~=" then adv(2); self.tokens[#self.tokens+1]={type=TK.NEQ,line=line}
        elseif p2=="<=" then adv(2); self.tokens[#self.tokens+1]={type=TK.LEQ,line=line}
        elseif p2==">=" then adv(2); self.tokens[#self.tokens+1]={type=TK.GEQ,line=line}
        elseif p2=="<<" then adv(2); self.tokens[#self.tokens+1]={type=TK.LSHIFT,line=line}
        elseif p2==">>" then adv(2); self.tokens[#self.tokens+1]={type=TK.RSHIFT,line=line}
        elseif p2=="//" then adv(2); self.tokens[#self.tokens+1]={type=TK.DSLASH,line=line}
        elseif p2=="::" then adv(2); self.tokens[#self.tokens+1]={type=TK.DCOLON,line=line}
        elseif p2=="+=" then adv(2); self.tokens[#self.tokens+1]={type=TK.PLUSEQ,line=line}
        elseif p2=="-=" then adv(2); self.tokens[#self.tokens+1]={type=TK.MINUSEQ,line=line}
        elseif p2=="*=" then adv(2); self.tokens[#self.tokens+1]={type=TK.STAREQ,line=line}
        elseif p2=="/=" then adv(2); self.tokens[#self.tokens+1]={type=TK.SLASHEQ,line=line}
        elseif p2=="%=" then adv(2); self.tokens[#self.tokens+1]={type=TK.PERCENTEQ,line=line}
        elseif p2=="^=" then adv(2); self.tokens[#self.tokens+1]={type=TK.CARETEQ,line=line}
        else
          adv()
          local sym={
            ["+"]=TK.PLUS,["-"]=TK.MINUS,["*"]=TK.STAR,["/"]=TK.SLASH,
            ["%"]=TK.PERCENT,["^"]=TK.CARET,["#"]=TK.HASH,["&"]=TK.AMP,
            ["|"]=TK.PIPE,["~"]=TK.TILDE,["<"]=TK.LT,[">"]=TK.GT,
            ["="]=TK.ASSIGN,["("]=TK.LPAREN,[")"]=TK.RPAREN,
            ["{"]=TK.LBRACE,["}"]=TK.RBRACE,["["]=TK.LBRACKET,["]"]=TK.RBRACKET,
            [";"]=TK.SEMI,[":"]=TK.COLON,[","]=TK.COMMA,["."]=TK.DOT,
          }
          if sym[c] then self.tokens[#self.tokens+1]={type=sym[c],line=line} end
        end
      end
    end
    return self.tokens
  end
  function self:peek(off) return self.tokens[self.ti+(off or 0)] or {type=TK.EOF,line=0} end
  function self:next() local t=self.tokens[self.ti] or {type=TK.EOF}; self.ti=self.ti+1; return t end
  function self:check(tp) return (self.tokens[self.ti] or {type=TK.EOF}).type==tp end
  function self:match(tp) if self:check(tp) then return self:next() end end
  function self:expect(tp)
    if not self:check(tp) then
      local t=self.tokens[self.ti] or {type="?",line="?"}
      die(("expected '%s' got '%s' at line %s"):format(tp, tostring(t.type), tostring(t.line)))
    end
    return self:next()
  end
  self:tokenize()
  return self
end

local OP={
  PUSH_NIL=1, PUSH_TRUE=2, PUSH_FALSE=3,
  PUSH_NUM=4, PUSH_STR=5, PUSH_VAR=6, PUSH_GLOBAL=7,
  POP=8, DUP=9, SWAP=10, ADJUST=11,
  SET_LOCAL=12, SET_GLOBAL=13, DEF_LOCAL=14,
  NEW_TABLE=15, GET_TABLE=16, SET_TABLE=17,
  GET_FIELD=18, SET_FIELD=19,
  ADD=20, SUB=21, MUL=22, DIV=23, MOD=24, POW=25, IDIV=26,
  UNM=27, NOT=28, LEN=29,
  BAND=30, BOR=31, BXOR=32, BNOT=33, SHL=34, SHR=35,
  CONCAT=36,
  EQ=37, NEQ=38, LT=39, GT=40, LEQ=41, GEQ=42,
  AND_JMP=43, OR_JMP=44,
  JMP=45, JMP_FALSE=46, JMP_TRUE=47,
  CALL=48, RETURN=49, TAILCALL=50,
  CLOSURE=51, SETLIST=52,
  FORPREP=53, FORLOOP=54,
  GFORPREP=55, GFORLOOP=56,
  ENTER_SCOPE=57, LEAVE_SCOPE=58,
  PUSH_VARARG=59,
  BIND_PARAM=60,
  BIND_FORVAR=61,
  BIND_GFORVARS=62,
  CALL_MULTI=63,
  TBL_SET_FIELD=64,
  TBL_SET_TABLE=65,
  RETURN_MULTI=66,
  CAPTURE_VARARG=67,
  SETLIST_MULTI=68,
  CALL_VARARG_TAIL=69,
  CALL_VARARG_TAIL_MULTI=70,
  -- ════════════════════════════════════════════════════
  -- 複合命令 (ChatGPT指摘1: opcode と処理の1対1対応を崩す)
  -- GCALL    : PUSH_GLOBAL[arg] + CALL[0] を1命令に融合
  --            arg = 関数名インデックス
  --            → 解析者には "opcode=GCALL" だけ見えてCALL+GETGLOBAL対応が隠れる
  -- PUSH_IMM : 即値整数を定数テーブルなしで直接pushする
  --            arg = 値そのもの (符号付き16bit範囲)
  --            → 定数テーブルと命令の対応関係を切断
  -- NUMOP    : ADD/SUB/MUL/DIV/MOD を1命令に統合。下位4bitが演算種別
  --            arg = (演算種別 & 0xF) | (ポップ数 << 4)
  --            → 「この命令は加算」という直接対応が消える
  -- GSET_TOP : スタックトップを GLOBAL[arg] に代入して pop
  --            arg = 名前インデックス
  --            → SET_GLOBAL + POP を1命令に融合
  -- ════════════════════════════════════════════════════
  GCALL=71,
  PUSH_IMM=72,
  NUMOP=73,
  GSET_TOP=74,
}

-- NUMOP の演算種別定数
local NUMOP_KIND = {ADD=0, SUB=1, MUL=2, DIV=3, MOD=4, POW=5, IDIV=6, CONCAT=7}

local function Compiler(lex, parent)
  local self={}
  self.code={}; self.consts={}; self.const_idx={}
  self.names={}; self.name_idx={}
  self.funcs={}; self.locals={}; self.scope={}
  self.parent=parent
  -- FIX: break文が emit(OP.JMP,0) するだけでパッチされておらず、常にオフセット0
  -- (=次の命令へ、実質何もしない)のままだったため break が機能していなかった。
  -- ループ開始時にbreakStackへ新しいリストをpushし、break文はそこへジャンプ命令の
  -- インデックスを記録、ループ終了時にそれら全てをループの外側へpatchする。
  self.breakStack={}

  local function emit(op,arg) self.code[#self.code+1]={op=op,arg=arg or 0}; return #self.code end
  local function patch(i,v) self.code[i].arg=v end
  local function here() return #self.code end
  local function addConst(v)
    local k=type(v)..":"..tostring(v)
    if not self.const_idx[k] then self.consts[#self.consts+1]=v; self.const_idx[k]=#self.consts end
    return self.const_idx[k]
  end
  local function addName(n)
    if not self.name_idx[n] then self.names[#self.names+1]=n; self.name_idx[n]=#self.names end
    return self.name_idx[n]
  end
  -- FIX: 外部(parseFuncBody)からパラメータ束縛コードを注入できるように公開
  self.emit=emit
  self.addName=addName
  -- FIX: isLocalが自分自身のlocalsしか見ておらず、ネストした関数(クロージャ)の
  -- 中で外側関数のローカル変数(upvalue)を参照すると常にfalseを返し、グローバル
  -- 変数として誤ってコンパイルされてしまうバグがあった。親コンパイラの連鎖を
  -- 辿って外側のローカル変数も見えるようにする。
  local function isLocal(n)
    local c=self
    while c do
      for i=#c.locals,1,-1 do if c.locals[i]==n then return true end end
      c=c.parent
    end
    return false
  end
  local function pushScope() self.scope[#self.scope+1]=#self.locals; emit(OP.ENTER_SCOPE) end
  local function popScope()
    local p=self.scope[#self.scope]; self.scope[#self.scope]=nil
    while #self.locals>p do self.locals[#self.locals]=nil end
    emit(OP.LEAVE_SCOPE)
  end

  local parseExpr, parseBlock, parseStat, parseTableConstructor, parseFuncBody

  local function parsePrimary()
    local t=lex:peek()
    if t.type==TK.NAME then
      lex:next()
      if isLocal(t.value) then emit(OP.PUSH_VAR, addName(t.value))
      else emit(OP.PUSH_GLOBAL, addName(t.value)) end
      return "name", t.value
    elseif t.type==TK.LPAREN then
      lex:next(); parseExpr(); lex:expect(TK.RPAREN)
      return "paren"
    else
      die("unexpected '"..tostring(t.type).."' at line "..tostring(t.line))
    end
  end

  local function parseCallArgs()
    local t=lex:peek()
    if t.type==TK.LPAREN then
      lex:next()
      local n=0
      local lastWasBareCall=false
      if not lex:check(TK.RPAREN) then
        lastWasBareCall=parseExpr(); n=1
        while lex:match(TK.COMMA) do lastWasBareCall=parseExpr(); n=n+1 end
      end
      lex:expect(TK.RPAREN)
      -- If the final argument was a bare function call (e.g. "f(table.unpack(t))"
      -- or "f(a, g())"), Lua semantics expand ALL of its return values in place,
      -- not just the first one. Report this back to the caller via a second
      -- return value so it can emit CALL_VARARG_TAIL instead of a plain CALL.
      return n, lastWasBareCall
    elseif t.type==TK.STRING then
      lex:next(); emit(OP.PUSH_STR, addConst(t.value)); return 1, false
    elseif t.type==TK.LBRACE then
      parseTableConstructor(); return 1, false
    else
      die("expected function args at line "..tostring(t.line))
    end
  end

  local function parseSuffixedExpr()
    -- 戻り値 kind: 最後に "call" ならこの式全体が(添字等を挟まず)単純呼び出しで
    -- 終わったことを示す。呼び出し元(generic forのin節)はこれを使って
    -- CALL→CALL_MULTIへの差し替え判断に利用する。
    local kind, name = parsePrimary()
    while true do
      local t=lex:peek()
      if t.type==TK.DOT then
        lex:next()
        local f=lex:expect(TK.NAME)
        emit(OP.GET_FIELD, addName(f.value))
        kind="index"; name=nil
      elseif t.type==TK.LBRACKET then
        lex:next(); parseExpr(); lex:expect(TK.RBRACKET)
        emit(OP.GET_TABLE)
        kind="index"; name=nil
      elseif t.type==TK.COLON then
        lex:next()
        local mn=lex:expect(TK.NAME)
        emit(OP.DUP)
        emit(OP.GET_FIELD, addName(mn.value))
        emit(OP.SWAP)
        local nargs,lastWasBareCall=parseCallArgs()
        if lastWasBareCall then
          local lastIns=self.code[#self.code]
          if lastIns and lastIns.op==OP.CALL then lastIns.op=OP.CALL_MULTI elseif lastIns and lastIns.op==OP.CALL_VARARG_TAIL then lastIns.op=OP.CALL_VARARG_TAIL_MULTI end
          -- nargs counts the trailing bare-call as 1 slot even though it expands
          -- to N values via CALL_MULTI; true fixed-arg count is nargs-1, plus 1
          -- for the implicit self argument = nargs.
          emit(OP.CALL_VARARG_TAIL, nargs)
        else
          emit(OP.CALL, nargs+1)
        end
        kind="call"; name=nil
      elseif t.type==TK.LPAREN or t.type==TK.STRING or t.type==TK.LBRACE then
        local nargs,lastWasBareCall=parseCallArgs()
        if lastWasBareCall then
          local lastIns=self.code[#self.code]
          if lastIns and lastIns.op==OP.CALL then lastIns.op=OP.CALL_MULTI elseif lastIns and lastIns.op==OP.CALL_VARARG_TAIL then lastIns.op=OP.CALL_VARARG_TAIL_MULTI end
          emit(OP.CALL_VARARG_TAIL, nargs-1)
        else
          emit(OP.CALL, nargs)
        end
        kind="call"; name=nil
      else break end
    end
    return kind, name
  end

  function parseTableConstructor()
    lex:expect(TK.LBRACE)
    emit(OP.NEW_TABLE)
    local count=0
    while not lex:check(TK.RBRACE) do
      local t=lex:peek()
      if t.type==TK.LBRACKET then
        lex:next(); parseExpr(); lex:expect(TK.RBRACKET)
        lex:expect(TK.ASSIGN); parseExpr()
        -- FIX: 代入文用のSET_TABLEはtableをpopしてしまい、テーブルコンストラクタの
        -- 用途(続くフィールドのためにtableをスタックに残す必要がある)と衝突していた。
        -- コンストラクタ専用のTBL_SET_TABLEを使う。
        emit(OP.TBL_SET_TABLE)
      elseif t.type==TK.NAME and lex:peek(1).type==TK.ASSIGN then
        local n=lex:next(); lex:next()
        parseExpr()
        -- FIX: 同様にSET_FIELDもtableを残さないため、コンストラクタ専用の
        -- TBL_SET_FIELDを使う。
        emit(OP.TBL_SET_FIELD, addName(n.value))
      elseif t.type==TK.DOTS then
        -- FIX: {...} のように可変長引数がテーブルの配列部要素として使われる場合、
        -- Lua仕様上その位置が最後の要素なら全展開される。PUSH_VARARGは複数値を
        -- 全部STへpushする実装にしたため、SETLIST(1個ずつ)ではなく専用の
        -- SETLIST_MULTIで、pushされた値を全てtableの配列部に追加する。
        lex:next(); emit(OP.PUSH_VARARG)
        emit(OP.SETLIST_MULTI, count)
      else
        local isBareCall = parseExpr()
        count=count+1
        local isLastElem = lex:check(TK.RBRACE) or (not lex:check(TK.COMMA) and not lex:check(TK.SEMI))
        if isBareCall and isLastElem then
          local lastIns=self.code[#self.code]
          if lastIns and lastIns.op==OP.CALL then lastIns.op=OP.CALL_MULTI elseif lastIns and lastIns.op==OP.CALL_VARARG_TAIL then lastIns.op=OP.CALL_VARARG_TAIL_MULTI end
          emit(OP.SETLIST_MULTI, count-1)
        else
          emit(OP.SETLIST, count)
        end
      end
      if not lex:match(TK.COMMA) then lex:match(TK.SEMI) end
      if lex:check(TK.RBRACE) then break end
    end
    lex:expect(TK.RBRACE)
  end

  function parseFuncBody()
    local sub=Compiler(lex, self)
    lex:expect(TK.LPAREN)
    local params={}
    local hasVararg=false
    if not lex:check(TK.RPAREN) then
      if lex:check(TK.DOTS) then lex:next(); hasVararg=true
      else
        local p=lex:expect(TK.NAME); params[#params+1]=p.value
        while lex:match(TK.COMMA) do
          if lex:check(TK.DOTS) then lex:next(); hasVararg=true; break end
          p=lex:expect(TK.NAME); params[#params+1]=p.value
        end
      end
    end
    lex:expect(TK.RPAREN)
    for _,p in ipairs(params) do sub.locals[#sub.locals+1]=p end
    -- FIX: 呼び出し時に初期スタック(ST)へ積まれた引数を、パラメータ名としてローカルスコープに束縛する。
    -- これが無いと関数本体内でパラメータ名を参照してもnilになり、かつ未消費の引数がスタックに
    -- 残ったまま後続のPUSH/CALL命令のスタック位置がズレて誤動作する原因になる。
    -- BIND_PARAM の arg はパラメータ名の name_idx。実行時は ST の先頭要素を1個ずつ
    -- table.remove(ST,1) で取り出し、その名前で SET_LOCAL する（呼び出し時の引数順=宣言順）。
    for _,p in ipairs(params) do
      sub.emit(OP.BIND_PARAM, sub.addName(p))
    end
    -- FIX: PUSH_VARARGが何もしない(noop)実装のままだったため `...` や
    -- `local args={...}` が常に空になっていた。固定パラメータを全てBIND_PARAM
    -- した後、STに残っている引数(=可変長引数)をCAPTURE_VARARGでVM内部の
    -- vararg保存領域にコピーし、PUSH_VARARGがそこから展開できるようにする。
    if hasVararg then
      sub.emit(OP.CAPTURE_VARARG)
    end
    sub:compileBlock()
    lex:expect(TK[TK.END] or TK.END)
    self.funcs[#self.funcs+1]={
      code=sub.code, consts=sub.consts, names=sub.names,
      funcs=sub.funcs, params=#params
    }
    return #self.funcs
  end

  local function parseSimpleExpr()
    local t=lex:peek()
    if t.type==TK.NUMBER then lex:next(); emit(OP.PUSH_NUM, addConst(t.value)); return false
    elseif t.type==TK.STRING then lex:next(); emit(OP.PUSH_STR, addConst(t.value)); return false
    elseif t.type==TK.TRUE then lex:next(); emit(OP.PUSH_TRUE); return false
    elseif t.type==TK.FALSE then lex:next(); emit(OP.PUSH_FALSE); return false
    elseif t.type==TK.NIL then lex:next(); emit(OP.PUSH_NIL); return false
    elseif t.type==TK.DOTS then lex:next(); emit(OP.PUSH_VARARG); return false
    elseif t.type==TK.FUNCTION then lex:next(); local fi=parseFuncBody(); emit(OP.CLOSURE,fi); return false
    elseif t.type==TK.LBRACE then parseTableConstructor(); return false
    else local k=parseSuffixedExpr(); return k=="call" end
  end

  local UNOP={[TK.MINUS]=OP.UNM,[TK.NOT]=OP.NOT,[TK.HASH]=OP.LEN,[TK.TILDE]=OP.BNOT}
  local BINPRIO={
    [TK.OR]={1,1},[TK.AND]={2,2},
    [TK.LT]={3,3},[TK.GT]={3,3},[TK.LEQ]={3,3},[TK.GEQ]={3,3},[TK.NEQ]={3,3},[TK.EQ]={3,3},
    [TK.PIPE]={4,4},[TK.TILDE]={5,5},[TK.AMP]={6,6},
    [TK.LSHIFT]={7,7},[TK.RSHIFT]={7,7},
    [TK.CONCAT]={8,7},
    [TK.PLUS]={9,9},[TK.MINUS]={9,9},
    [TK.STAR]={10,10},[TK.SLASH]={10,10},[TK.DSLASH]={10,10},[TK.PERCENT]={10,10},
    [TK.CARET]={12,11},
  }
  local BINOP_EMIT={
    [TK.PLUS]=OP.ADD,[TK.MINUS]=OP.SUB,[TK.STAR]=OP.MUL,[TK.SLASH]=OP.DIV,
    [TK.PERCENT]=OP.MOD,[TK.CARET]=OP.POW,[TK.DSLASH]=OP.IDIV,
    [TK.AMP]=OP.BAND,[TK.PIPE]=OP.BOR,[TK.TILDE]=OP.BXOR,
    [TK.LSHIFT]=OP.SHL,[TK.RSHIFT]=OP.SHR,[TK.CONCAT]=OP.CONCAT,
    [TK.EQ]=OP.EQ,[TK.NEQ]=OP.NEQ,[TK.LT]=OP.LT,[TK.GT]=OP.GT,
    [TK.LEQ]=OP.LEQ,[TK.GEQ]=OP.GEQ,
  }

  parseExpr = function(limit)
    limit=limit or 0
    local t=lex:peek()
    local uop=UNOP[t.type]
    local isBareCall
    if uop then lex:next(); parseExpr(11); emit(uop); isBareCall=false
    else isBareCall=parseSimpleExpr() end
    local prio=BINPRIO[lex:peek().type]
    while prio and prio[1]>limit do
      local op=lex:next()
      isBareCall=false
      if op.type==TK.AND then
        local j=emit(OP.AND_JMP,0); parseExpr(prio[2]); patch(j,here()-j)
      elseif op.type==TK.OR then
        local j=emit(OP.OR_JMP,0); parseExpr(prio[2]); patch(j,here()-j)
      else
        parseExpr(prio[2]); emit(BINOP_EMIT[op.type] or OP.ADD)
      end
      prio=BINPRIO[lex:peek().type]
    end
    return isBareCall
  end

  local function parseExprList()
    local n=1; local lastIsBareCall=parseExpr()
    while lex:match(TK.COMMA) do lastIsBareCall=parseExpr(); n=n+1 end
    return n, lastIsBareCall
  end

  local function parseAssignOrCall()
    local lhs={}
    local function parseLhsOne()
      local t=lex:peek()
      if t.type~=TK.NAME then die("expected name at line "..tostring(t.line)) end
      lex:next()
      local base={name=t.value, suffixes={}}
      -- NOTE ON EVALUATION ORDER (bugfix): GET_TABLE/SET_TABLE pop the stack as
      -- key-then-table (key must be on top, table beneath it) — see the VM's
      -- GET_TABLE handler, which does `local k=pop(); local t=pop(); push(t[k])`.
      -- Index-key expressions ("[expr]") must therefore be evaluated and pushed
      -- AFTER the container is already on the stack, never before. The previous
      -- version called parseExpr() for each "[expr]" suffix immediately while
      -- prescanning suffixes here, before the caller ever pushed the container —
      -- producing a [key, table] stack instead of [table, key], which silently
      -- swapped the two for every indexed read/write. This version still
      -- prescans suffix *shape* (field name, or "there is an index expression
      -- here") into base.suffixes for the caller to know what it's dealing with,
      -- but for index_expr suffixes it stores the already-correctly-ordered fact
      -- that a key expression follows; the actual GET_TABLE/SET_TABLE emission
      -- (which needs the container pushed first) still happens in the caller,
      -- exactly as before — the fix here is narrower: index_expr suffixes must
      -- only have their key expression parsed+emitted at a point where the
      -- container is guaranteed to already be on the stack beneath them. Since
      -- this prescan function doesn't know whether the caller will push the
      -- container before or after calling this, and every caller in this file
      -- pushes the container first and then walks base.suffixes emitting
      -- GET_TABLE/GET_FIELD per entry, we defer key-expression parsing itself
      -- into a closure stored on the suffix, to be invoked by the caller at the
      -- correct point (container already pushed) instead of eagerly here.
      while true do
        local p=lex:peek()
        if p.type==TK.DOT then
          lex:next(); local f=lex:expect(TK.NAME)
          base.suffixes[#base.suffixes+1]={type="field",val=f.value}
        elseif p.type==TK.LBRACKET then
          lex:next()
          -- The key expression must be parsed HERE, in its correct source
          -- position (this parser makes a single linear pass over tokens, so
          -- parsing it later — e.g. inside a closure invoked by the caller —
          -- would read whatever tokens happen to be at the cursor at that
          -- later time, not this expression). However, the *value* it
          -- produces must not enter the runtime stack yet: the container this
          -- key applies to hasn't been pushed by the caller yet, and
          -- GET_TABLE/SET_TABLE require [container, key] stack order. So:
          -- parse+evaluate the key now, immediately stash it into a compiler-
          -- internal temp local, and let emitKey() (invoked later by the
          -- caller, once the container is on the stack) simply push that saved
          -- value back — no re-parsing, no re-evaluation, correct order.
          parseExpr()
          local tmpKeyName = "__vmobf_key_" .. tostring(#self.locals+1) .. "_" .. V()
          self.locals[#self.locals+1]=tmpKeyName
          emit(OP.SET_LOCAL,addName(tmpKeyName))
          local keyEmitter = function() emit(OP.PUSH_VAR,addName(tmpKeyName)) end
          lex:expect(TK.RBRACKET)
          base.suffixes[#base.suffixes+1]={type="index_expr", emitKey=keyEmitter}
        elseif p.type==TK.COLON or p.type==TK.LPAREN or p.type==TK.STRING or p.type==TK.LBRACE then
          if isLocal(base.name) then emit(OP.PUSH_VAR,addName(base.name))
          else emit(OP.PUSH_GLOBAL,addName(base.name)) end
          for _,s in ipairs(base.suffixes) do
            if s.type=="field" then emit(OP.GET_FIELD,addName(s.val))
            elseif s.type=="index_expr" then s.emitKey(); emit(OP.GET_TABLE) end
          end
          while true do
            local q=lex:peek()
            if q.type==TK.COLON then
              lex:next(); local mn=lex:expect(TK.NAME)
              emit(OP.DUP); emit(OP.GET_FIELD,addName(mn.value)); emit(OP.SWAP)
              local na,lastWasBareCall=parseCallArgs()
              if lastWasBareCall then
                local lastIns=self.code[#self.code]
                if lastIns and lastIns.op==OP.CALL then lastIns.op=OP.CALL_MULTI elseif lastIns and lastIns.op==OP.CALL_VARARG_TAIL then lastIns.op=OP.CALL_VARARG_TAIL_MULTI end
                emit(OP.CALL_VARARG_TAIL,na) -- na-1 fixed + 1 implicit self = na
              else
                emit(OP.CALL,na+1)
              end
            elseif q.type==TK.LPAREN or q.type==TK.STRING or q.type==TK.LBRACE then
              local na,lastWasBareCall=parseCallArgs()
              if lastWasBareCall then
                local lastIns=self.code[#self.code]
                if lastIns and lastIns.op==OP.CALL then lastIns.op=OP.CALL_MULTI elseif lastIns and lastIns.op==OP.CALL_VARARG_TAIL then lastIns.op=OP.CALL_VARARG_TAIL_MULTI end
                emit(OP.CALL_VARARG_TAIL,na-1)
              else
                emit(OP.CALL,na)
              end
            elseif q.type==TK.DOT then
              lex:next(); local f=lex:expect(TK.NAME); emit(OP.GET_FIELD,addName(f.value))
            elseif q.type==TK.LBRACKET then
              lex:next(); parseExpr(); lex:expect(TK.RBRACKET); emit(OP.GET_TABLE)
            else break end
          end
          return nil
        else break end
      end
      return base
    end
    local first=parseLhsOne()
    if first==nil then emit(OP.POP); return end
    lhs[1]=first

    -- Luau compound assignment: "lhs OP= rhs" desugars to "lhs = lhs OP rhs".
    -- Must be checked before the TK.COMMA multi-assign loop below, since
    -- compound assignment never has multiple lhs targets (e.g. "a, b += 1, 2"
    -- is not valid Luau any more than it's valid Lua).
    local COMPOUND_OP = {
      [TK.PLUSEQ]="ADD", [TK.MINUSEQ]="SUB", [TK.STAREQ]="MUL",
      [TK.SLASHEQ]="DIV", [TK.DSLASHEQ]="IDIV", [TK.PERCENTEQ]="MOD",
      [TK.CARETEQ]="POW", [TK.CONCATEQ]="CONCAT",
    }
    local compoundOpName = COMPOUND_OP[lex:peek().type]
    if compoundOpName then
      lex:next() -- consume the compound-assignment operator token
      local b = first
      if #b.suffixes==0 then
        -- simple name target: push current value, push rhs, combine, store back
        if isLocal(b.name) then emit(OP.PUSH_VAR,addName(b.name))
        else emit(OP.PUSH_GLOBAL,addName(b.name)) end
        parseExpr()
        emit(OP[compoundOpName])
        if isLocal(b.name) then emit(OP.SET_LOCAL,addName(b.name))
        else emit(OP.SET_GLOBAL,addName(b.name)) end
      else
        -- field/index target: push the container, resolve all suffixes except the
        -- last to get to the immediate parent table, then read-combine-write the
        -- final field/index without re-evaluating any index expression twice.
        if isLocal(b.name) then emit(OP.PUSH_VAR,addName(b.name))
        else emit(OP.PUSH_GLOBAL,addName(b.name)) end
        for si=1,#b.suffixes-1 do
          local s=b.suffixes[si]
          if s.type=="field" then emit(OP.GET_FIELD,addName(s.val))
          else s.emitKey(); emit(OP.GET_TABLE) end
        end
        local last=b.suffixes[#b.suffixes]
        if last.type=="field" then
          -- stack: [table] ; GET_FIELD doesn't consume table, so DUP then GET_FIELD
          -- reads the current value while keeping table on the stack for SET_FIELD.
          emit(OP.DUP); emit(OP.GET_FIELD,addName(last.val))
          parseExpr()
          emit(OP[compoundOpName])
          emit(OP.SET_FIELD,addName(last.val))
        else
          -- Indexed target "container[expr] OP= rhs". Stack right now, after
          -- resolving every suffix-before-last above, is just [..., container]
          -- — the key expression has NOT been evaluated yet (emitKey() is
          -- deferred; see parseLhsOne). Evaluate it now, immediately after the
          -- container so the runtime stack order is [container, key] as
          -- GET_TABLE requires, then stash the key in a temp local so it can be
          -- reused for both the read (GET_TABLE) and the write (SET_TABLE)
          -- without a second evaluation of the index expression (which would
          -- double any side effects, e.g. "t[f()] += 1" calling f() twice).
          last.emitKey() -- stack: [..., container, key]
          local tmpKey = "__vmobf_ckey_" .. tostring(#self.locals+1) .. "_" .. V()
          local tmpVal = "__vmobf_cval_" .. tostring(#self.locals+1) .. "_" .. V()
          self.locals[#self.locals+1]=tmpKey
          emit(OP.SET_LOCAL,addName(tmpKey)) -- pops key; stack: [..., container]
          emit(OP.PUSH_VAR,addName(tmpKey))
          emit(OP.GET_TABLE) -- stack: [..., container[key]]
          parseExpr() -- rhs; stack: [..., container[key], rhs]
          emit(OP[compoundOpName]) -- stack: [..., combined]
          self.locals[#self.locals+1]=tmpVal
          emit(OP.SET_LOCAL,addName(tmpVal)) -- stash result; stack: [...]
          -- Re-push the container prefix for the write. This re-evaluates
          -- b.name plus any suffixes before the last one a second time — an
          -- accepted trade-off shared by most languages' compound-assignment
          -- desugaring (e.g. "a.b.c[k] += 1" re-evaluates "a.b" but not "k").
          if isLocal(b.name) then emit(OP.PUSH_VAR,addName(b.name))
          else emit(OP.PUSH_GLOBAL,addName(b.name)) end
          for si=1,#b.suffixes-1 do
            local s=b.suffixes[si]
            if s.type=="field" then emit(OP.GET_FIELD,addName(s.val))
            else s.emitKey(); emit(OP.GET_TABLE) end
          end
          emit(OP.PUSH_VAR,addName(tmpKey))
          emit(OP.PUSH_VAR,addName(tmpVal))
          emit(OP.SET_TABLE)
        end
      end
      return
    end

    while lex:check(TK.COMMA) do
      lex:next()
      local extra=parseLhsOne()
      if extra==nil then die("unexpected call in lhs") end
      lhs[#lhs+1]=extra
    end
    lex:expect(TK.ASSIGN)
    -- FIX: 多重代入(local a,b,c = f())で、右辺の最後の式が呼び出しの場合はLua仕様
    -- 上「多値展開」される。以前はCALLが常に1値に切り詰められるため、a,b,cの
    -- うちaにしか値が入らず、b,cはADJUSTの無限ループバグ(nilを番兵無しで積もう
    -- としていた)と相まって壊れていた。ここでは最後の式が単純呼び出しならCALL_MULTI
    -- に差し替え、戻り値の実数はADJUSTが実行時に#lhsへ調整する。
    local nvals,lastIsBareCall=parseExprList()
    if lastIsBareCall then
      local lastIns=self.code[#self.code]
      if lastIns and lastIns.op==OP.CALL then lastIns.op=OP.CALL_MULTI elseif lastIns and lastIns.op==OP.CALL_VARARG_TAIL then lastIns.op=OP.CALL_VARARG_TAIL_MULTI end
    end
    if nvals~=#lhs or lastIsBareCall then emit(OP.ADJUST,#lhs) end
    for i=#lhs,1,-1 do
      local b=lhs[i]
      if #b.suffixes==0 then
        if isLocal(b.name) then emit(OP.SET_LOCAL,addName(b.name))
        else emit(OP.SET_GLOBAL,addName(b.name)) end
      else
        -- BUGFIX: the value to assign is already on the stack top at this point
        -- (pushed by parseExprList() above, before any of these per-target
        -- pushes). SET_FIELD/SET_TABLE both expect value on top (they pop
        -- value first, then table/key) — so the value must be stashed, the
        -- container+suffixes+key pushed underneath in the right order, and the
        -- value pushed back on top immediately before the SET_* instruction.
        local tmpVal = "__vmobf_asgn_" .. tostring(#self.locals+1) .. "_" .. V()
        self.locals[#self.locals+1]=tmpVal
        emit(OP.SET_LOCAL,addName(tmpVal)) -- stash pending value
        if isLocal(b.name) then emit(OP.PUSH_VAR,addName(b.name))
        else emit(OP.PUSH_GLOBAL,addName(b.name)) end
        for si=1,#b.suffixes-1 do
          local s=b.suffixes[si]
          if s.type=="field" then emit(OP.GET_FIELD,addName(s.val))
          else s.emitKey(); emit(OP.GET_TABLE) end
        end
        local last=b.suffixes[#b.suffixes]
        if last.type=="field" then
          emit(OP.PUSH_VAR,addName(tmpVal))
          emit(OP.SET_FIELD,addName(last.val))
        else
          last.emitKey()
          emit(OP.PUSH_VAR,addName(tmpVal))
          emit(OP.SET_TABLE)
        end
      end
    end
  end

  parseStat = function()
    local t=lex:peek()
    if t.type==TK.SEMI then lex:next(); return true
    elseif t.type==TK.IF then
      lex:next(); parseExpr(); lex:expect(TK.THEN)
      local jf=emit(OP.JMP_FALSE,0)
      pushScope(); parseBlock(); popScope()
      local exits={}
      while lex:check(TK.ELSEIF) do
        lex:next()
        exits[#exits+1]=emit(OP.JMP,0)
        patch(jf,here()-jf)
        parseExpr(); lex:expect(TK.THEN)
        jf=emit(OP.JMP_FALSE,0)
        pushScope(); parseBlock(); popScope()
      end
      if lex:match(TK.ELSE) then
        exits[#exits+1]=emit(OP.JMP,0)
        patch(jf,here()-jf)
        pushScope(); parseBlock(); popScope()
      else
        patch(jf,here()-jf)
      end
      for _,e in ipairs(exits) do patch(e,here()-e) end
      lex:expect(TK.END)
    elseif t.type==TK.WHILE then
      lex:next()
      local ls=here()
      parseExpr()
      local jf=emit(OP.JMP_FALSE,0)
      lex:expect(TK.DO)
      self.breakStack[#self.breakStack+1]={}
      pushScope(); parseBlock(); popScope()
      lex:expect(TK.END)
      emit(OP.JMP, ls-here()-1)
      patch(jf,here()-jf)
      local bl=table.remove(self.breakStack)
      for _,bi in ipairs(bl) do patch(bi, here()-bi) end
    elseif t.type==TK.DO then
      lex:next(); pushScope(); parseBlock(); popScope(); lex:expect(TK.END)
    elseif t.type==TK.FOR then
      lex:next()
      local var=lex:expect(TK.NAME)
      if lex:check(TK.ASSIGN) then
        lex:next(); parseExpr(); lex:expect(TK.COMMA); parseExpr()
        if lex:match(TK.COMMA) then parseExpr()
        else emit(OP.PUSH_NUM,addConst(1)) end
        lex:expect(TK.DO)
        local fp=emit(OP.FORPREP,0)
        self.locals[#self.locals+1]=var.value
        -- FIX: 数値forのループ変数はスタック上(st/lim/stpの一番下)に留まるだけで
        -- ローカルスコープに束縛されないため、本体内で参照するとnilになっていた。
        -- また ENTER_SCOPE/LEAVE_SCOPE を lb(ジャンプ先)より前に置くと、初回しか
        -- ENTER_SCOPEが実行されないのに毎周LEAVE_SCOPEだけ実行され、2周目以降で
        -- スコープスタックが枯渇するバグになる。ENTER/LEAVEを lb..FORLOOP の
        -- 範囲(=毎周実行される範囲)に含める。
        local lb=here()
        self.breakStack[#self.breakStack+1]={}
        pushScope()
        emit(OP.BIND_FORVAR, addName(var.value))
        parseBlock(); popScope(); lex:expect(TK.END)
        emit(OP.FORLOOP, lb-here()-1)
        patch(fp,here()-fp)
        local bl=table.remove(self.breakStack)
        for _,bi in ipairs(bl) do patch(bi, here()-bi) end
      else
        local names={var.value}
        while lex:match(TK.COMMA) do names[#names+1]=lex:expect(TK.NAME).value end
        lex:expect(TK.IN)
        -- FIX: generic forの `in` 節 (explist) は、Lua仕様上「最後の式だけ多値展開」
        -- される。典型的には `in ipairs(t) do` のように1つの呼び出し式が3値
        -- (iterator,state,control)を返す。このVMのCALLは通常1値に切り詰める
        -- ようにしたため、ここでは最後の式が(演算子を挟まない)単純な呼び出し式
        -- で終わっていれば、そのCALL命令をCALL_MULTIに差し替えて全戻り値をpushさせる。
        local lastIsBareCall = parseExpr()
        while lex:match(TK.COMMA) do lastIsBareCall = parseExpr() end
        if lastIsBareCall then
          local lastIns=self.code[#self.code]
          if lastIns and lastIns.op==OP.CALL then lastIns.op=OP.CALL_MULTI elseif lastIns and lastIns.op==OP.CALL_VARARG_TAIL then lastIns.op=OP.CALL_VARARG_TAIL_MULTI end
        end
        lex:expect(TK.DO)
        local gfp=emit(OP.GFORPREP,0)
        for _,n in ipairs(names) do self.locals[#self.locals+1]=n end
        -- FIX: generic forの複数ループ変数(i,v等)もスタックに積まれるだけで
        -- ローカルスコープに束縛されていなかった。ループ本体の先頭(=GFORLOOPの
        -- ジャンプ先)で毎回SET_LOCALする。lb はこの束縛命令群の直前に置き、
        -- GFORLOOPが毎周ここへ戻って来るたびに再束縛されるようにする。
        -- BIND_GFORVARS は毎回 ri をインクリメントしながら results[ri] を取得するため、
        -- names は宣言順のままemitする(names[1]→results[1], names[2]→results[2], ...)。
        -- また ENTER_SCOPE も lb..GFORLOOP の範囲(毎周実行される範囲)に含める必要がある
        -- (数値forと同じ理由: 初回しかENTER_SCOPEが走らないとスコープが枯渇する)。
        local lb=here()
        self.breakStack[#self.breakStack+1]={}
        pushScope()
        for _,n in ipairs(names) do emit(OP.BIND_GFORVARS, addName(n)) end
        parseBlock(); popScope(); lex:expect(TK.END)
        emit(OP.GFORLOOP, lb-here()-1)
        patch(gfp,here()-gfp)
        local bl=table.remove(self.breakStack)
        for _,bi in ipairs(bl) do patch(bi, here()-bi) end
      end
    elseif t.type==TK.REPEAT then
      lex:next()
      local ls=here()
      self.breakStack[#self.breakStack+1]={}
      pushScope(); parseBlock()
      lex:expect(TK.UNTIL); parseExpr(); popScope()
      emit(OP.JMP_FALSE, ls-here()-1)
      local bl=table.remove(self.breakStack)
      for _,bi in ipairs(bl) do patch(bi, here()-bi) end
    elseif t.type==TK.FUNCTION then
      lex:next()
      local name=lex:expect(TK.NAME)
      local fields={}; local is_method=false
      while lex:match(TK.DOT) do fields[#fields+1]=lex:expect(TK.NAME).value end
      if lex:match(TK.COLON) then fields[#fields+1]=lex:expect(TK.NAME).value; is_method=true end
      local fi=parseFuncBody(); emit(OP.CLOSURE,fi)
      if #fields==0 then
        if isLocal(name.value) then emit(OP.SET_LOCAL,addName(name.value))
        else emit(OP.SET_GLOBAL,addName(name.value)) end
      else
        if isLocal(name.value) then emit(OP.PUSH_VAR,addName(name.value))
        else emit(OP.PUSH_GLOBAL,addName(name.value)) end
        for i=1,#fields-1 do emit(OP.GET_FIELD,addName(fields[i])) end
        emit(OP.SET_FIELD,addName(fields[#fields]))
      end
    elseif t.type==TK.LOCAL then
      lex:next()
      if lex:check(TK.FUNCTION) then
        lex:next(); local nm=lex:expect(TK.NAME)
        self.locals[#self.locals+1]=nm.value
        local fi=parseFuncBody(); emit(OP.CLOSURE,fi)
        emit(OP.SET_LOCAL,addName(nm.value))
      else
        local names={}; names[#names+1]=lex:expect(TK.NAME).value
        while lex:match(TK.COMMA) do names[#names+1]=lex:expect(TK.NAME).value end
        local nv=0
        local lastIsBareCall=false
        if lex:match(TK.ASSIGN) then nv,lastIsBareCall=parseExprList() end
        -- FIX: local a,b,c = f() のように最後の式が呼び出しで終わる場合、Lua仕様上
        -- 多値展開される。CALLをCALL_MULTIに差し替え、ADJUSTで#namesへ調整する。
        if lastIsBareCall then
          local lastIns=self.code[#self.code]
          if lastIns and lastIns.op==OP.CALL then lastIns.op=OP.CALL_MULTI elseif lastIns and lastIns.op==OP.CALL_VARARG_TAIL then lastIns.op=OP.CALL_VARARG_TAIL_MULTI end
        end
        if nv~=#names or lastIsBareCall then emit(OP.ADJUST,#names) end
        for i=#names,1,-1 do
          self.locals[#self.locals+1]=names[i]
          emit(OP.SET_LOCAL,addName(names[i]))
        end
      end
    elseif t.type==TK.RETURN then
      lex:next()
      local nv=0
      local lastIsBareCall=false
      if not (lex:check(TK.END) or lex:check(TK.ELSE) or lex:check(TK.ELSEIF)
           or lex:check(TK.UNTIL) or lex:check(TK.EOF)) then
        nv,lastIsBareCall=parseExprList()
      end
      -- FIX: return f() のように最後の式が呼び出しで終わる場合、Lua仕様上
      -- fの全戻り値がそのまま返される(多値展開)。CALLをCALL_MULTIに差し替える。
      -- RETURN自体は arg(=nv、式の個数)個をpopして返すが、CALL_MULTIで
      -- 複数値が積まれていた場合はADJUSTで実際の個数に揃えてから返す必要がある。
      if lastIsBareCall then
        local lastIns=self.code[#self.code]
        if lastIns and lastIns.op==OP.CALL then lastIns.op=OP.CALL_MULTI elseif lastIns and lastIns.op==OP.CALL_VARARG_TAIL then lastIns.op=OP.CALL_VARARG_TAIL_MULTI end
        emit(OP.RETURN_MULTI, nv-1)
      else
        emit(OP.RETURN,nv)
      end
      lex:match(TK.SEMI)
    elseif t.type==TK.BREAK then
      lex:next()
      local bi=emit(OP.JMP,0)
      local bl=self.breakStack[#self.breakStack]
      if bl then bl[#bl+1]=bi end
    elseif t.type==TK.GOTO then
      lex:next(); lex:next()
    elseif t.type==TK.DCOLON then
      lex:next(); lex:next(); lex:expect(TK.DCOLON)
    elseif t.type==TK.NAME then
      parseAssignOrCall()
    else return false end
    return true
  end

  parseBlock = function()
    while true do
      local t=lex:peek()
      if t.type==TK.EOF or t.type==TK.END or t.type==TK.ELSE
        or t.type==TK.ELSEIF or t.type==TK.UNTIL then break end
      if not parseStat() then break end
    end
  end

  function self:compileBlock() parseBlock() end
  function self:compile()
    parseBlock(); emit(OP.RETURN,0)
    return {code=self.code,consts=self.consts,names=self.names,funcs=self.funcs,params=0}
  end
  return self
end

local lex=Lexer(source)
local compiler=Compiler(lex)
local ok,result=pcall(function() return compiler:compile() end)
if not ok then
  io.stderr:write("VM_OBF_WARN: compile failed: "..tostring(result).."\nFalling back to encrypted source\n")
  local sa,sb,sc=seed,(seed*22695477+1)%4294967296,(seed*1103515245+12345)%4294967296
  local function prng2()
    sa=(sa*1664525+1013904223)%4294967296
    sb=(sb*22695477+1)%4294967296
    sc=(sc*1103515245+12345)%4294967296
    local v=sa; v=v-sb; if v<0 then v=v+4294967296 end
    return (v+sc)%4294967296%256
  end
  local CHSZ=math.max(32,math.floor(#source/16))
  local chs,cvars={},{}
  local p3=1
  while p3<=#source do
    local cd=source:sub(p3,p3+CHSZ-1); p3=p3+CHSZ
    local k3=prng2()%40+5
    local enc={}
    -- ★ FIX: %255+1方式 値域1..255、 絶対なし
    for i=1,#cd do enc[i]=ne((cd:byte(i)+k3+(i%7)*3-1)%255+1) end
    local vt,vr,vi=V(),V(),V()
    chs[#chs+1]=("(function()local %s={%s};local %s={};for %s=1,#%s do %s[%s]=string.char((%s[%s]-1-%d-%s%%7*3+1020)%%255+1)end;return table.concat(%s)end)()"):format(
      vt,table.concat(enc,","),vr,vi,vt,vr,vi,vt,vi,k3,vi,vr)
    cvars[#cvars+1]=V()
  end
  local ord={}; for i=1,#chs do ord[i]=i end
  for i=#ord,2,-1 do local j=(rng()%i)+1; ord[i],ord[j]=ord[j],ord[i] end
  local lsk=(rng()%40)+5; local lse={}
  for i=1,#"loadstring" do lse[i]=ne(("loadstring"):byte(i)+lsk) end
  local vLt,vLr,vLi,vLn,vLf=V(),V(),V(),V(),V()
  local ls2=("local %s={%s};local %s={};for %s=1,#%s do %s[%s]=string.char(%s[%s]-%d)end;local %s=table.concat(%s);local %s=_G[%s] or loadstring"):format(
    vLt,table.concat(lse,","),vLr,vLi,vLt,vLr,vLi,vLt,vLi,lsk,vLn,vLr,vLf,vLn)
  local sv={}; for i=1,#ord do sv[i]=cvars[ord[i]] end
  local vS=V()
  local fl={"(function()"}; fl[#fl+1]=ls2
  for i=1,#chs do fl[#fl+1]=("local %s=%s"):format(cvars[i],chs[i]) end
  fl[#fl+1]=("local %s=%s"):format(vS,table.concat(sv,".."))
  fl[#fl+1]=("local _f,_e=%s(%s);if _f then _f() else error(_e) end"):format(vLf,vS)
  fl[#fl+1]="end)()"
  local fw=io.open(output_file,"w"); if not fw then die("cannot write") end
  fw:write(table.concat(fl,"\n")); fw:close()
  io.write("OK:"..output_file); os.exit(0)
end

local proto=result

-- ════════════════════════════════════════════════════
-- Peephole Optimizer: 複合命令への変換
-- (ChatGPT指摘1: opcode と処理の1対1対応を崩す)
-- ════════════════════════════════════════════════════
-- 命令ストリームを走査して、単純な命令シーケンスを
-- 複合命令に置き換える。これにより:
--   1. opcode → 処理 の1対1対応が崩れる
--   2. 定数テーブルを参照する命令が減る (PUSH_IMM で直接値を埋め込む)
--   3. 命令数が増えず、VM自体もコンパクトになる

local function peepholeOptimize(p)
  if not p or not p.code then return p end
  local code = p.code
  local new_code = {}
  local i = 1
  -- Lua5.1互換: goto不使用、if/elseif チェーンで分岐
  local arith_map = {
    [OP.ADD]=NUMOP_KIND.ADD, [OP.SUB]=NUMOP_KIND.SUB,
    [OP.MUL]=NUMOP_KIND.MUL, [OP.DIV]=NUMOP_KIND.DIV,
    [OP.MOD]=NUMOP_KIND.MOD, [OP.POW]=NUMOP_KIND.POW,
    [OP.IDIV]=NUMOP_KIND.IDIV, [OP.CONCAT]=NUMOP_KIND.CONCAT,
  }
  while i <= #code do
    local ins = code[i]
    local next1 = code[i+1]
    local consumed = 1
    local fused = nil

    -- パターン1: PUSH_GLOBAL[k] + CALL[0] → GCALL[k]
    -- 引数なし呼び出しのみ融合（引数ありはPUSHとCALLの間に引数のPUSH命令が入るため融合不可）
    if ins.op == OP.PUSH_GLOBAL and next1 and next1.op == OP.CALL and next1.arg == 0 then
      fused = {op=OP.GCALL, arg=ins.arg}
      consumed = 2

    -- パターン2: PUSH_NUM (小整数) → PUSH_IMM
    elseif ins.op == OP.PUSH_NUM then
      local v = p.consts[ins.arg]
      if type(v)=="number" and v==math.floor(v) and v>=-16384 and v<=16383 then
        fused = {op=OP.PUSH_IMM, arg=math.floor(v)+16384}
      end

    -- パターン3: 算術演算 → NUMOP
    elseif arith_map[ins.op] then
      fused = {op=OP.NUMOP, arg=arith_map[ins.op]}

    -- パターン4: SET_GLOBAL + POP → GSET_TOP
    elseif ins.op == OP.SET_GLOBAL and next1 and next1.op == OP.POP then
      fused = {op=OP.GSET_TOP, arg=ins.arg}
      consumed = 2
    end

    new_code[#new_code+1] = fused or ins
    i = i + consumed
  end

  -- JMP系の参照先(arg)を新しい命令インデックスに再マッピング
  -- old_idx → new_idx のマップを作成
  -- 注: 上記変換で命令数が減る場合があるため、オフセットが変わる
  -- 簡易版: 削除された命令の位置を記録してオフセットを調整
  -- (JMP arg は絶対インデックスではなく相対オフセット)
  -- → 現在の実装では JMP は相対オフセット形式なので
  --   命令数が変わった場合は再計算が必要

  -- old_indices[new_idx] = old_idx を記録しておく
  -- → 今は各パターンが 1→1 or 2→1 なので、削除された命令の old_idx を追跡
  -- 簡単のため: old code の各インデックスが new code の何番目になるかを記録
  local old_to_new = {}
  local ni = 1
  local oi = 1
  -- 再走査してマッピングを作成
  local oi2 = 1
  local ni2 = 1
  local code2 = p.code  -- 元
  local old_to_new2 = {}
  while oi2 <= #code2 do
    old_to_new2[oi2] = ni2
    local ins2 = code2[oi2]
    local nx1 = code2[oi2+1]
    -- 同じ変換ロジックで何命令消費したかを判定
    local consumed = 1
    if ins2.op==OP.PUSH_GLOBAL and nx1 and nx1.op==OP.CALL and nx1.arg==0 then
      consumed=2
    elseif ins2.op==OP.SET_GLOBAL and nx1 and nx1.op==OP.POP then
      consumed=2
    end
    oi2 = oi2 + consumed
    ni2 = ni2 + 1
  end
  old_to_new2[#code2+1] = ni2  -- 末尾sentinel

  -- JMP/JMP_FALSE/JMP_TRUE/AND_JMP/OR_JMP/FORPREP/FORLOOP/GFORPREP/GFORLOOP の
  -- arg (相対オフセット) を再計算
  local jmp_ops = {
    [OP.JMP]=true,[OP.JMP_FALSE]=true,[OP.JMP_TRUE]=true,
    [OP.AND_JMP]=true,[OP.OR_JMP]=true,
    [OP.FORPREP]=true,[OP.FORLOOP]=true,
    [OP.GFORPREP]=true,[OP.GFORLOOP]=true,
  }
  for ni_jmp=1,#new_code do
    local ins_jmp = new_code[ni_jmp]
    if jmp_ops[ins_jmp.op] then
      -- 元の命令インデックスを逆引き
      local old_idx = nil
      for oi_k,ni_k in pairs(old_to_new2) do
        if ni_k == ni_jmp then old_idx=oi_k; break end
      end
      if old_idx then
        local old_arg = ins_jmp.arg
        local old_target = old_idx + old_arg  -- 元のJMP先(絶対)
        local new_target = old_to_new2[old_target] or old_target
        ins_jmp.arg = new_target - ni_jmp  -- 新しい相対オフセット
      end
    end
  end

  p.code = new_code
  -- 再帰的にサブ関数も変換
  for _,sub in ipairs(p.funcs or {}) do peepholeOptimize(sub) end
  return p
end

proto = peepholeOptimize(proto)

-- DATAFLOW-HARDENING: ジャンク(無害な無意味)命令をバイトコード中に挿入する。
-- 挿入するのは「即値をpushして直後にpopするだけ」のスタック中立な2命令
-- (PUSH_IMM + POP)で、実行結果・スタック状態・変数の値には一切影響しない。
-- これにより、バイトコードを逐次読んでいる解析者から見ると、実際のデータの
-- 流れ(push→演算→storeの連鎖)の間に本物らしい無関係な命令が混ざることに
-- なり、「どの命令が実際の計算に寄与しているか」の判別が難しくなる
-- (Data Flow Obfuscation)。JMP系命令の相対オフセットは、挿入前後の命令
-- インデックス対応表(old_to_new)を使って正確に再計算するため、挿入によって
-- 制御フロー(if/while/forの分岐先)が壊れることはない。
local function injectDataFlowJunk(p, strength_)
  if not p or not p.code then return p end
  local code = p.code
  if #code==0 then return p end
  -- strength(1〜15)に応じて挿入確率をスケーリングする
  -- strength=1で約3%、strength=15で約20%の命令位置の直前にジャンクが挿入される
  local chance = 0.03 + (strength_-1) * 0.012
  local new_code = {}
  local old_to_new = {}
  for oi=1,#code do
    if math.random() < chance then
      -- PUSH_IMM(16bit符号付き範囲をoffset+16384で表現、0..32767で全域カバー)
      new_code[#new_code+1] = {op=OP.PUSH_IMM, arg=math.random(0,32767)}
      new_code[#new_code+1] = {op=OP.POP, arg=0}
    end
    old_to_new[oi] = #new_code+1
    new_code[#new_code+1] = code[oi]
  end
  old_to_new[#code+1] = #new_code+1 -- 末尾(ブロック末尾へのジャンプ)用のsentinel

  local jmp_ops = {
    [OP.JMP]=true,[OP.JMP_FALSE]=true,[OP.JMP_TRUE]=true,
    [OP.AND_JMP]=true,[OP.OR_JMP]=true,
    [OP.FORPREP]=true,[OP.FORLOOP]=true,
    [OP.GFORPREP]=true,[OP.GFORLOOP]=true,
  }
  for oi=1,#code do
    local ins = code[oi]
    if jmp_ops[ins.op] then
      local old_target = oi + ins.arg
      local new_target = old_to_new[old_target] or old_target
      local new_self = old_to_new[oi]
      new_code[new_self].arg = new_target - new_self
    end
  end

  p.code = new_code
  for _,sub in ipairs(p.funcs or {}) do injectDataFlowJunk(sub, strength_) end
  return p
end

math.randomseed(seed)
-- ジャンク命令挿入はシード依存の乱数を使うため、randomseed()の後に実行し
-- --seed指定時の再現性を保つ。
proto = injectDataFlowJunk(proto, strength)
local MAX_OP=74  -- 複合命令追加分を反映
-- strength(1〜15)に応じてディスパッチバンド数をスケーリング（strength=5で従来値(2,4)相当）
local DISPATCH_BAND_MAX = math.max(2, math.floor(2 + strength*0.5))
local DISPATCH_BAND_COUNT = math.random(2, DISPATCH_BAND_MAX)
-- Each band occupies a widely-separated numeric range so a coarse range check
-- can cheaply tell which band vOP falls into before doing the usual linear
-- opcode comparison within that band. Band 0 keeps the original 1..MAX_OP
-- range (so unshuffled/legacy assumptions about small values stay harmless);
-- other bands are offset by a random large multiple of 10000 per band so
-- ranges never collide and are trivially distinguishable by simple comparisons.
local bandOffsets = {0}
do
  local usedOffsets = {[0]=true}
  for b=2,DISPATCH_BAND_COUNT do
    local off
    repeat off = (math.random(1,50)) * 10000 until not usedOffsets[off]
    usedOffsets[off]=true
    bandOffsets[b]=off
  end
end
local pool={}; for i=1,MAX_OP do pool[i]=i end
for i=MAX_OP,2,-1 do local j=math.random(1,i); pool[i],pool[j]=pool[j],pool[i] end
-- Assign each opcode slot (1..MAX_OP) to a random band, then its final shuffled
-- value is (band's base permutation value) + (band's offset).
local opBand={}
for i=1,MAX_OP do opBand[i]=math.random(1,DISPATCH_BAND_COUNT) end
local op2c={}; local c2op={}
for i=1,MAX_OP do
  local band = opBand[i]
  local val = pool[i] + bandOffsets[band]
  op2c[i]=val; c2op[val]=i
end

local function remap(p)
  for _,ins in ipairs(p.code) do ins.op=op2c[ins.op] or ins.op end
  for _,f in ipairs(p.funcs) do remap(f) end
end
remap(proto)

-- HARDENING: 命令をビットパック整数に変換する
-- pack = op * 65536 + (arg + 32768)
-- これにより {op=N, arg=M} の平文テーブルが数値の羅列になり、
-- 解読ツールが「ここが命令列だ」と特定しにくくなる。
-- さらに全命令を単一XOR鍵で暗号化し、整合性チェックと連動させる。
local PACK_KEY = math.random(1, 0x7FFF)  -- ランダムな暗号化鍵

local function packInstr(op, arg)
  -- op: shuffled opcode value, arg: signed integer
  -- ビットパック: op<<16 | (arg+32768) → 1整数
  -- さらにPACK_KEYでXOR(下位16ビットのみ): Lua5.1にビット演算子がないため
  -- 加減算で模擬する
  local raw = op * 65536 + (arg + 32768)
  -- XOR下位16ビット: raw XOR (PACK_KEY<<0)
  -- Lua5.1互換XOR (下位16ビットのみ)
  local lo = raw % 65536
  local hi = math.floor(raw / 65536)
  -- loとPACK_KEYのXOR(Lua5.1互換)
  local xlo = 0
  local a, b = lo, PACK_KEY
  for _=0,15 do
    if math.floor(a)%2 ~= math.floor(b)%2 then xlo = xlo + 1 end
    xlo = xlo * 0  -- reset; use math approach below
    break
  end
  -- シンプルな方法: (lo + PACK_KEY) % 65536 （XORの近似、完璧ではないが解析を困難にする）
  -- 実際のXORはLua5.1では高コストなので加算で代替
  local enc_lo = (lo + PACK_KEY) % 65536
  return hi * 65536 + enc_lo
end

local function serial(p)
  local kp={}
  for _,c in ipairs(p.consts) do
    if type(c)=="number" then
      if c==math.floor(c) and math.abs(c)<1e12 then kp[#kp+1]=ne(math.floor(c))
      else kp[#kp+1]=obfuscate_float(c) end
    elseif type(c)=="string" then kp[#kp+1]=hide_str(c)
    else kp[#kp+1]=tostring(c) end
  end
  local np={}
  for _,n in ipairs(p.names) do np[#np+1]=hide_str(n) end
  -- 命令をビットパック整数としてシリアライズ
  local cp={}
  for _,ins in ipairs(p.code) do
    local packed = packInstr(ins.op, ins.arg)
    cp[#cp+1] = ne(packed)
  end
  local fp={}
  for _,sub in ipairs(p.funcs) do fp[#fp+1]=serial(sub) end
  -- フォーマット変更: c は整数配列(旧: テーブル配列)
  return ("{k={%s},n={%s},c={%s},f={%s},p=%s,_pk=%s}"):format(
    table.concat(kp,","),table.concat(np,","),table.concat(cp,","),
    table.concat(fp,","),ne(p.params or 0),ne(PACK_KEY))
end

local proto_str=serial(proto)

-- HARDENING: c2op(シャッフル後の値→実オペコード)を単一の連想配列として
-- 露出させず、複数のシャード(部分テーブル)に分割し、シャードごとにテーブル
-- リテラル形式かif/elseif形式かをランダムに選んでレンダリングする。
-- 1つの「対応表」を一望できないようにし、静的解析には複数の関数呼び出しと
-- 分岐条件を辿らせる必要がある構造にする。
local function buildShardedResolver()
  local keys = {}
  for k in pairs(c2op) do keys[#keys+1] = k end
  -- shuffle key order so shard membership doesn't correlate with opcode value
  for i=#keys,2,-1 do local j=math.random(1,i); keys[i],keys[j]=keys[j],keys[i] end

  -- strength(1〜15)に応じてシャード数をスケーリング（strength=5で従来値(3,6)相当）
  local shardMax = math.max(3, math.floor(3 + strength*0.6))
  local shardCount = math.random(3, shardMax)
  local shards = {}
  for i=1,shardCount do shards[i] = {} end
  for i,k in ipairs(keys) do
    local s = ((i-1) % shardCount) + 1
    shards[s][#shards[s]+1] = k
  end

  local vResolve = V()
  local shardFnNames = {}
  local preLines = {}
  for si,shard in ipairs(shards) do
    local vShardFn = V()
    shardFnNames[si] = vShardFn
    local style = math.random(1,2)
    if style==1 or #shard==0 then
      -- table-literal shard: {[k]=v,...}
      local parts = {}
      for _,k in ipairs(shard) do parts[#parts+1] = ("[%s]=%s"):format(ne(k), ne(c2op[k])) end
      local vTbl = V()
      preLines[#preLines+1] = ("local %s={%s}"):format(vTbl, table.concat(parts,","))
      preLines[#preLines+1] = ("local function %s(_k) return %s[_k] end"):format(vShardFn, vTbl)
    else
      -- if/elseif-chain shard: no table literal at all for this shard
      local vA = V()
      local body = {}
      for ki,k in ipairs(shard) do
        local kw = (ki==1) and "if" or "elseif"
        body[#body+1] = ("  %s %s==%s then return %s"):format(kw, vA, ne(k), ne(c2op[k]))
      end
      preLines[#preLines+1] = ("local function %s(%s)"):format(vShardFn, vA)
      for _,ln in ipairs(body) do preLines[#preLines+1]=ln end
      preLines[#preLines+1] = "  end"
      preLines[#preLines+1] = "end"
    end
  end

  -- HARDENING (two-tier dispatch): route to the right shard via band first.
  -- Each opcode's shuffled value already lives in one of DISPATCH_BAND_COUNT
  -- disjoint numeric ranges (band 0 is 1..MAX_OP, other bands are offset by a
  -- random multiple of 10000 — see bandOffsets above). The resolver first does
  -- a coarse range check to find which band a key falls in, then only needs a
  -- per-band routing table (much smaller and less revealing than one flat
  -- table covering every opcode) to find the shard within that band.
  local perBandRouting = {} -- band index -> { [key]=shardIndex, ... } (as ne() parts)
  for b=1,DISPATCH_BAND_COUNT do perBandRouting[b] = {} end
  for i,k in ipairs(keys) do
    local s = ((i-1) % shardCount) + 1
    -- Determine which band this key's value belongs to by checking range
    -- membership against bandOffsets (band b's range is [offset+1, offset+MAX_OP]).
    local band = 1
    for b=DISPATCH_BAND_COUNT,1,-1 do
      if k > bandOffsets[b] and k <= bandOffsets[b]+MAX_OP then band=b; break end
    end
    perBandRouting[band][#perBandRouting[band]+1] = ("[%s]=%s"):format(ne(k), ne(s))
  end

  local vRoute = V()
  local vBandLo, vBandHi = V(), V()
  -- Emit one small per-band routing table, plus a coarse band-selector function
  -- that picks the right table via range comparison before doing the lookup.
  local bandTblNames = {}
  for b=1,DISPATCH_BAND_COUNT do
    local vBTbl = V()
    bandTblNames[b] = vBTbl
    local parts = perBandRouting[b]
    preLines[#preLines+1] = ("local %s={%s}"):format(vBTbl, table.concat(parts, ","))
  end
  local vBandSelect = V()
  do
    local body = {}
    -- Sort bands by offset descending so the range checks (k > offset) find the
    -- correct (highest matching) band first, mirroring how band membership was
    -- computed above.
    local order = {}
    for b=1,DISPATCH_BAND_COUNT do order[#order+1]=b end
    table.sort(order, function(a,c) return bandOffsets[a] > bandOffsets[c] end)
    for oi,b in ipairs(order) do
      local kw = (oi==1) and "if" or "elseif"
      body[#body+1] = ("  %s _k>%s then return %s"):format(kw, ne(bandOffsets[b]), bandTblNames[b])
    end
    preLines[#preLines+1] = ("local function %s(_k)"):format(vBandSelect)
    for _,ln in ipairs(body) do preLines[#preLines+1]=ln end
    preLines[#preLines+1] = "  end"
    preLines[#preLines+1] = ("  return %s"):format(bandTblNames[1])
    preLines[#preLines+1] = "end"
  end

  local vShardTbl = V()
  local shardRefs = {}
  for si,fn in ipairs(shardFnNames) do shardRefs[#shardRefs+1] = fn end
  preLines[#preLines+1] = ("local %s={%s}"):format(vShardTbl, table.concat(shardRefs,","))
  preLines[#preLines+1] = ("local function %s(_k) return %s[%s(_k)[_k]](_k) end"):format(vResolve, vShardTbl, vBandSelect)

  return vResolve, table.concat(preLines, "\n")
end

local vUM_resolver, vUM_setup = buildShardedResolver()

-- CFF-HARDENING: opc()が呼ばれた順序(=各オペコードハンドラブロックが
-- lines[]へ出力される順序と1対1)を記録しておく。これにより、後段の
-- ディスパッチ再構築フェーズで「このブロックがどのOpcodeのハンドラか」を
-- テキスト解析（数値リテラル抽出）に頼らず正確に特定でき、Opcodeの
-- 所属バンドに基づいた階層的(ネスト)ディスパッチを安全に構築できる。
local opcCallOrder = {}
local function opc(name) opcCallOrder[#opcCallOrder+1]=name; return ne(OP[name]) end

local lines={}; local function L(s) lines[#lines+1]=s end

local vUM=V(); local vPR=V(); local vVM=V()
local vF=V(); local vST=V(); local vEN=V(); local vUV=V(); local vPC=V()
local vIN=V(); local vOP=V(); local vAR=V()

-- ★ Lua5.1互換ビット演算ヘルパー関数名
local vBIT=V()

L("local _=0;(function()")
L(integrityFnSource)
L(vUM_setup)
L(("local %s=%s"):format(vUM,vUM_resolver))
L(("local %s=%s"):format(vPR,proto_str))

-- ★ ビット演算ヘルパー (Lua5.1互換・bit32使用 → Roblox標準)
-- 独自実装は遅くてバグりやすいので bit32 に切り替え
L(("local %s=bit32 or {}"):format(vBIT))
L("if not bit32 then")
L("  local function _xor(a,b) local r=0;for i=0,31 do local x=math.floor(a/2^i)%2;local y=math.floor(b/2^i)%2;if x~=y then r=r+2^i end end;return r end")
L("  local function _and(a,b) local r=0;for i=0,31 do if math.floor(a/2^i)%2==1 and math.floor(b/2^i)%2==1 then r=r+2^i end end;return r end")
L("  local function _or(a,b) local r=0;for i=0,31 do if math.floor(a/2^i)%2==1 or math.floor(b/2^i)%2==1 then r=r+2^i end end;return r end")
L("  local function _not(a) local r=0;for i=0,31 do if math.floor(a/2^i)%2==0 then r=r+2^i end end;return r end")
L("  local function _shl(a,b) return math.floor(a*(2^b))%4294967296 end")
L("  local function _shr(a,b) return math.floor(a/(2^b)) end")
L(("  %s.bxor=_xor;%s.band=_and;%s.bor=_or;%s.bnot=_not;%s.lshift=_shl;%s.rshift=_shr"):format(vBIT,vBIT,vBIT,vBIT,vBIT,vBIT))
L("end")

-- FIX: Luau(play.luau.orgなど)には標準の _G テーブルが存在しない
-- (Luauの最小限の標準ライブラリには含まれていない)。そのため
-- 環境テーブルが未指定のとき `or _G` が nil になり、以降のグローバル変数
-- 参照(printの呼び出し等)が軒並み失敗していた。
-- _G が使えるLua5.1/5.4等ではそちらを優先しつつ、Luauのように _G が無い
-- 環境でも動くよう、既知の標準グローバル/ライブラリを個別にpcallで拾って
-- フォールバック環境テーブルを構築する(存在しないグローバルを直接書くと
-- 環境によってはコンパイルエラーになりうるため、1つずつ安全に取得する)。
L("local function _tryget(name, getter)")
L("  local ok, v = pcall(getter)")
L("  if ok then return v end")
L("  return nil")
L("end")
L("local _FALLBACK_ENV = _G")
L("if _FALLBACK_ENV == nil then")
L("  _FALLBACK_ENV = {}")
L("  local _E = _FALLBACK_ENV")
L("  _E.print=_tryget('print',function() return print end)")
L("  _E.type=_tryget('type',function() return type end)")
L("  _E.tostring=_tryget('tostring',function() return tostring end)")
L("  _E.tonumber=_tryget('tonumber',function() return tonumber end)")
L("  _E.pairs=_tryget('pairs',function() return pairs end)")
L("  _E.ipairs=_tryget('ipairs',function() return ipairs end)")
L("  _E.next=_tryget('next',function() return next end)")
L("  _E.select=_tryget('select',function() return select end)")
L("  _E.error=_tryget('error',function() return error end)")
L("  _E.assert=_tryget('assert',function() return assert end)")
L("  _E.pcall=_tryget('pcall',function() return pcall end)")
L("  _E.xpcall=_tryget('xpcall',function() return xpcall end)")
L("  _E.setmetatable=_tryget('setmetatable',function() return setmetatable end)")
L("  _E.getmetatable=_tryget('getmetatable',function() return getmetatable end)")
L("  _E.rawget=_tryget('rawget',function() return rawget end)")
L("  _E.rawset=_tryget('rawset',function() return rawset end)")
L("  _E.rawequal=_tryget('rawequal',function() return rawequal end)")
L("  _E.rawlen=_tryget('rawlen',function() return rawlen end)")
L("  _E.unpack=_tryget('unpack',function() return unpack end)")
L("  _E.require=_tryget('require',function() return require end)")
L("  _E.string=_tryget('string',function() return string end)")
L("  _E.table=_tryget('table',function() return table end)")
L("  _E.math=_tryget('math',function() return math end)")
L("  _E.os=_tryget('os',function() return os end)")
L("  _E.coroutine=_tryget('coroutine',function() return coroutine end)")
L("  _E.bit32=_tryget('bit32',function() return bit32 end)")
L("  _E.utf8=_tryget('utf8',function() return utf8 end)")
L("  _E.buffer=_tryget('buffer',function() return buffer end)")
L("  _E.task=_tryget('task',function() return task end)")
L("  _E.vector=_tryget('vector',function() return vector end)")
L("  _E.game=_tryget('game',function() return game end)")
L("  _E.workspace=_tryget('workspace',function() return workspace end)")
L("  _E.script=_tryget('script',function() return script end)")
L("  _E.wait=_tryget('wait',function() return wait end)")
L("  _E.spawn=_tryget('spawn',function() return spawn end)")
L("  _E.delay=_tryget('delay',function() return delay end)")
L("  _E.tick=_tryget('tick',function() return tick end)")
L("  _E.warn=_tryget('warn',function() return warn end)")
L("  _E.typeof=_tryget('typeof',function() return typeof end)")
L("  _E.newproxy=_tryget('newproxy',function() return newproxy end)")
L("  _E.Instance=_tryget('Instance',function() return Instance end)")
L("  _E.Vector3=_tryget('Vector3',function() return Vector3 end)")
L("  _E.Vector2=_tryget('Vector2',function() return Vector2 end)")
L("  _E.CFrame=_tryget('CFrame',function() return CFrame end)")
L("  _E.Color3=_tryget('Color3',function() return Color3 end)")
L("  _E.UDim2=_tryget('UDim2',function() return UDim2 end)")
L("  _E.UDim=_tryget('UDim',function() return UDim end)")
L("  _E.BrickColor=_tryget('BrickColor',function() return BrickColor end)")
L("  _E.Enum=_tryget('Enum',function() return Enum end)")
L("  _E.Ray=_tryget('Ray',function() return Ray end)")
L("  _E.Region3=_tryget('Region3',function() return Region3 end)")
L("  _E._G=_E")
L("end")

L(("local %s"):format(vVM))
L(("%s=function(%s,%s,%s,%s)"):format(vVM,vF,vST,vEN,vUV))
L(("  %s=%s or {}"):format(vST,vST))
L(("  %s=%s or _FALLBACK_ENV"):format(vEN,vEN))
L(("  %s=%s or {}"):format(vUV,vUV))
L(("  local %s=%s.k"):format("_K",vF))
L(("  local %s=%s.n"):format("_N",vF))
L(("  local %s=1"):format(vPC))
L("  local _unpack=table.unpack or unpack")
-- FIX: 呼び出し結果を {f(...)} でテーブル化すると、戻り値の末尾にnilが含まれる
-- 場合(例: pairs()は3番目にnilを返す) #演算子で要素数が正しく取れない
-- (Luaの仕様上、nilを含む配列の長さは未定義動作になりうる)バグがあった。
-- table.pack相当のヘルパーを用意し、.nフィールドで正確な個数を保持する。
L("  local _pack=table.pack or function(...) return {n=select('#',...), ...} end")
-- FIX: 式評価用スタック(ST)は ST[#ST+1]=v という「配列の末尾に積む」実装のため、
-- v が nil だと実質何も起きず(Luaのテーブルにnilを代入するのは要素削除と同義)、
-- スタックの見かけの長さが変わらずGFORPREP等の複数pop処理が壊れるバグがあった。
-- ST上でnilを表すための番兵値を用意し、CALL_MULTI等でpushする際はnilの代わりに
-- この番兵を積み、pop側(GFORPREP/GFORLOOP)で番兵を実際のnilに変換して使う。
local vNILSENT=V()
L(("  local %s=setmetatable({},{__tostring=function() return 'nil' end})"):format(vNILSENT))
local vSCOPE=V()
-- FIX: クロージャ(ネストした関数)が外側関数のローカル変数(upvalue)を参照できな
-- かったバグを修正。以前は毎回のVM呼び出しで vSCOPE={{}} と真っさらに初期化して
-- いたため、子関数は親のスコープに一切アクセスできなかった。
-- ここでは第4引数(vUV)として「呼び出し元スコープチェーンのコピー」を受け取り、
-- それをベースに新しいスコープを1段追加する。CLOSURE命令側で、クロージャ生成時点
-- の vSCOPE 全体をコピーして子VM呼び出しの第4引数として渡すようにする。
local vSCOPE_base=V()
L(("  local %s={}"):format(vSCOPE_base))
L(("  for _si=1,#%s do %s[_si]=%s[_si] end"):format(vUV,vSCOPE_base,vUV))
L(("  %s[#%s+1]={}"):format(vSCOPE_base,vSCOPE_base))
L(("  local %s=%s"):format(vSCOPE,vSCOPE_base))
local vSET_L=V(); local vGET_L=V()
L(("  local function %s(nm,val)"):format(vSET_L))
L(("    for _i=#%s,1,-1 do if %s[_i][nm]~=nil then %s[_i][nm]=val;return end end"):format(vSCOPE,vSCOPE,vSCOPE))
L(("    %s[#%s][nm]=val"):format(vSCOPE,vSCOPE))
L("  end")
L(("  local function %s(nm)"):format(vGET_L))
L(("    for _i=#%s,1,-1 do local v=%s[_i][nm];if v~=nil then return v end end"):format(vSCOPE,vSCOPE))
L("  end")
-- FIX: 数値for/generic forの内部状態(st/lim/stp や f/s/i)を式評価用スタック(ST)と
-- 共有すると、ループ本体内の式評価(push/pop)がそれらを巻き込んで破壊してしまう。
-- そのため専用のフレームスタックを別に用意し、本体側のSTとは独立させる。
local vNFOR=V(); local vGFOR=V()
L(("  local %s={}"):format(vNFOR))
L(("  local %s={}"):format(vGFOR))
-- FIX: PUSH_VARARGが常にnoopだったため `...` が機能していなかった。
-- CAPTURE_VARARGが固定パラメータ消費後の残りSTをここに保存し、PUSH_VARARGが
-- それをSTへ展開する。
local vVARARG=V()
L(("  local %s={n=0}"):format(vVARARG))
-- FIX: SETLIST_MULTIが「直前のPUSH_VARARG/CALL_MULTIが何個の値をpushしたか」を
-- 知るための記録用変数。
local vLASTMULTI=V()
L(("  local %s=0"):format(vLASTMULTI))

L("  while true do")
-- ビットパックデコード: 整数 → op(上位16bit) + arg(下位16bit-32768)
-- _F._pk は serial() が埋め込んだ暗号化鍵
L(("    local %s=%s.c[%s]"):format(vIN,vF,vPC))
L(("    if not %s then break end"):format(vIN))
-- hi = floor(packed / 65536) = shuffled opcode
-- lo_enc = packed % 65536 = (arg+32768+PACK_KEY)%65536
-- lo_dec = (lo_enc - PACK_KEY + 65536) % 65536
-- arg = lo_dec - 32768
L(("    local _hi=math.floor(%s/65536)"):format(vIN))
L(("    local _lo=(%s%%65536-%s._pk+65536)%%65536"):format(vIN,vF))
L(("    local %s=%s(_hi)"):format(vOP,vUM))
L(("    local %s=_lo-32768"):format(vAR))
L(("    %s=%s+1"):format(vPC,vPC))

-- HARDENING: 以降、各オペコードハンドラのブロックが始まる。解析耐性強化のため、
-- 生成完了後にこの区間の elseif ブロックをシャッフルし出現順を毎回変える
-- (ハンドラの実行ロジック自体は一切変更しない、ブロック単位の並び替えのみ)。
-- NOTE: マーカーの実際の設置位置は、ヘルパー関数定義(_popv/pop_expr/push_expr/
-- top_expr)より後、最初の本物のオペコードハンドラ(PUSH_NIL)の直前でなければ
-- ならない。ヘルパー定義行を誤って「最初のブロック」としてシャッフル範囲に
-- 含めてしまうと、シャッフル後にそれが elseif として書き換えられ構文が壊れる
-- ため、マーカーはこれらの前置きコードの生成が完了した直後に置く(下記)。

-- FIX: ST上のnilは番兵値(vNILSENT)で表現されている場合があるため、pop時に
-- 自動的に実際のnilへ変換するヘルパーを用意し、全てのpop_expr呼び出しが
-- 透過的に正しいnil値を受け取れるようにする。
L(("  local function _popv(t) local v=table.remove(t); if v==%s then return nil end; return v end"):format(vNILSENT))
local function pop_expr() return ("_popv(%s)"):format(vST) end
local function push_expr(v) return ("%s[#%s+1]=%s"):format(vST,vST,v) end
local function top_expr() return ("%s[#%s]"):format(vST,vST) end

local DISPATCH_BLOCK_START = #lines + 1

L(("    if %s==%s then %s"):format(vOP,opc("PUSH_NIL"),push_expr("nil")))
L(("    elseif %s==%s then %s"):format(vOP,opc("PUSH_TRUE"),push_expr("true")))
L(("    elseif %s==%s then %s"):format(vOP,opc("PUSH_FALSE"),push_expr("false")))
L(("    elseif %s==%s then %s"):format(vOP,opc("PUSH_NUM"),push_expr("_K["..vAR.."]")))
L(("    elseif %s==%s then %s"):format(vOP,opc("PUSH_STR"),push_expr("_K["..vAR.."]")))
-- FIX: PUSH_VARARG — CAPTURE_VARARGが保存したvararg値を全てSTへ展開する。
-- nilが含まれていても正しく扱えるよう番兵値を使う。
L(("    elseif %s==%s then for _vi=1,%s.n do local _v=%s[_vi]; %s end; %s=%s.n"):format(
  vOP,opc("PUSH_VARARG"),vVARARG,vVARARG,push_expr("(_v==nil and "..vNILSENT.." or _v)"),vLASTMULTI,vVARARG))
-- FIX: CAPTURE_VARARG — 固定パラメータをBIND_PARAMで全て消費した後、STに残って
-- いる引数(=可変長引数)を vararg保存領域にコピーする。.nで正確な個数を保持する
-- (残りの引数にnilが含まれる可能性は低いが念のため番兵経由で扱う)。
L(("    elseif %s==%s then local _vn=#%s; %s={n=_vn}; for _vi=1,_vn do %s[_vi]=%s[_vi] end; for _vi=1,_vn do %s[_vi]=nil end"):format(
  vOP,opc("CAPTURE_VARARG"),vST,vVARARG,vVARARG,vST,vST))
-- FIX: BIND_PARAM — 呼び出し時にSTの先頭に積まれた引数を1個ずつ取り出し、
-- パラメータ名としてローカルスコープにSET_LOCALする。これが無いと関数内で
-- パラメータ名を参照してもnilになり、かつ未消費の引数がスタックに残留して
-- 後続のPUSH/CALL命令のスタック位置がズレる。
L(("    elseif %s==%s then local %s=table.remove(%s,1);%s(_N[%s],%s)"):format(
  vOP,opc("BIND_PARAM"),"_bp",vST,vSET_L,vAR,"_bp"))
local vv1=V()
L(("    elseif %s==%s then local %s=%s(_N[%s]);%s"):format(vOP,opc("PUSH_VAR"),vv1,vGET_L,vAR,push_expr(vv1)))
local vv2=V()
L(("    elseif %s==%s then local %s=%s[_N[%s]];%s"):format(vOP,opc("PUSH_GLOBAL"),vv2,vEN,vAR,push_expr(vv2)))
L(("    elseif %s==%s then %s"):format(vOP,opc("POP"),pop_expr()))
local vv3=V()
L(("    elseif %s==%s then local %s=%s;%s"):format(vOP,opc("DUP"),vv3,top_expr(),push_expr(vv3)))
local vs1=V(); local vs2=V()
L(("    elseif %s==%s then local %s=%s;local %s=%s;"):format(vOP,opc("SWAP"),vs1,pop_expr(),vs2,pop_expr()))
L(("      %s;%s"):format(push_expr(vs1),push_expr(vs2)))
-- FIX: ADJUST が push_expr("nil") で不足分を埋めようとしていたが、
-- ST[#ST+1]=nil は実質何もしない(Luaのnil代入は要素削除と同義)ため #ST が
-- 増えず無限ループするバグがあった。nilの代わりに番兵値を積み、代入先で
-- 番兵をnilに変換して使う(SET_LOCAL/SET_GLOBALで変換)。
L(("    elseif %s==%s then while #%s<%s do %s end;while #%s>%s do %s end"):format(
  vOP,opc("ADJUST"),vST,vAR,push_expr(vNILSENT),vST,vAR,pop_expr()))
local vsl=V()
L(("    elseif %s==%s then local %s=%s;%s(_N[%s],%s)"):format(vOP,opc("SET_LOCAL"),vsl,pop_expr(),vSET_L,vAR,vsl))
local vsg=V()
L(("    elseif %s==%s then local %s=%s;%s[_N[%s]]=%s"):format(vOP,opc("SET_GLOBAL"),vsg,pop_expr(),vEN,vAR,vsg))
local vdl=V()
L(("    elseif %s==%s then local %s=%s;%s[#%s][_N[%s]]=%s"):format(vOP,opc("DEF_LOCAL"),vdl,pop_expr(),vSCOPE,vSCOPE,vAR,vdl))
L(("    elseif %s==%s then %s"):format(vOP,opc("NEW_TABLE"),push_expr("{}")))
local vgt_k=V(); local vgt_t=V()
L(("    elseif %s==%s then local %s=%s;local %s=%s;%s"):format(vOP,opc("GET_TABLE"),vgt_k,pop_expr(),vgt_t,pop_expr(),push_expr(vgt_t.."["..vgt_k.."]")))
local vst_v=V(); local vst_k=V(); local vst_t=V()
L(("    elseif %s==%s then local %s=%s;local %s=%s;local %s=%s;%s[%s]=%s"):format(
  vOP,opc("SET_TABLE"),vst_v,pop_expr(),vst_k,pop_expr(),vst_t,pop_expr(),vst_t,vst_k,vst_v))
local vgf_t=V()
L(("    elseif %s==%s then local %s=%s;%s"):format(vOP,opc("GET_FIELD"),vgf_t,pop_expr(),push_expr(vgf_t.."[_N["..vAR.."]]")))
local vsf_v=V(); local vsf_t=V()
L(("    elseif %s==%s then local %s=%s;local %s=%s;%s[_N[%s]]=%s"):format(
  vOP,opc("SET_FIELD"),vsf_v,pop_expr(),vsf_t,pop_expr(),vsf_t,vAR,vsf_v))
local vlist_v=V(); local vlist_t=V()
L(("    elseif %s==%s then local %s=%s;local %s=%s[#%s];%s[%s]=%s"):format(
  vOP,opc("SETLIST"),vlist_v,pop_expr(),vlist_t,vST,vST,vlist_t,vAR,vlist_v))

-- FIX: SETLIST_MULTI — {...} や末尾の関数呼び出しがテーブルコンストラクタの
-- 最後の配列要素として使われる場合、Lua仕様上その全戻り値/可変長引数が展開
-- されて連番で格納される。直前のPUSH_VARARG/CALL_MULTIが何個pushしたかを
-- vLASTMULTI に記録しておき、ここでその個数分だけpopしてテーブルに連番格納する。
local vlm_i=V(); local vlm_v=V(); local vlm_t=V()
L(("    elseif %s==%s then"):format(vOP,opc("SETLIST_MULTI")))
L(("      local %s={}"):format(vlm_v))
L(("      for %s=1,%s do %s[%s]=%s end"):format(vlm_i,vLASTMULTI,vlm_v,vlm_i,pop_expr()))
L(("      local %s=%s[#%s]"):format(vlm_t,vST,vST))
L(("      for %s=1,%s do %s[%s+%s]=%s[%s] end"):format(vlm_i,vLASTMULTI,vlm_t,vAR,vlm_i,vlm_v,vlm_i))

-- FIX: TBL_SET_FIELD / TBL_SET_TABLE — テーブルコンストラクタ専用。
-- 代入文用のSET_FIELD/SET_TABLEはtableをpopして戻さないため、コンストラクタの
-- 「複数フィールドを積み上げて構築する」用途(tableをスタックに残し続ける必要が
-- ある)と衝突していた。SETLISTと同様、valueだけpopしテーブルはST[#ST]参照のまま残す。
local vtsf_v=V(); local vtsf_t=V()
L(("    elseif %s==%s then local %s=%s;local %s=%s[#%s];%s[_N[%s]]=%s"):format(
  vOP,opc("TBL_SET_FIELD"),vtsf_v,pop_expr(),vtsf_t,vST,vST,vtsf_t,vAR,vtsf_v))
local vtst_v=V(); local vtst_k=V(); local vtst_t=V()
L(("    elseif %s==%s then local %s=%s;local %s=%s;local %s=%s[#%s];%s[%s]=%s"):format(
  vOP,opc("TBL_SET_TABLE"),vtst_v,pop_expr(),vtst_k,pop_expr(),vtst_t,vST,vST,vtst_t,vtst_k,vtst_v))

-- ★ 算術演算 (bit32 使用)
local function arith(opname, op_sym)
  local va=V(); local vb=V()
  L(("    elseif %s==%s then local %s=%s;local %s=%s;%s"):format(
    vOP,opc(opname),vb,pop_expr(),va,pop_expr(),push_expr(va..op_sym..vb)))
end
-- ★ FIX: shl/shr は bit32.lshift/rshift を使う (独自実装の shl/shr → lshift/rshift)
local function arith_fn(opname, fn_name)
  local va=V(); local vb=V()
  L(("    elseif %s==%s then local %s=%s;local %s=%s;%s"):format(
    vOP,opc(opname),vb,pop_expr(),va,pop_expr(),push_expr(vBIT.."."..fn_name.."("..va..","..vb..")")))
end
local function unary_fn(opname, fn_name)
  local va=V()
  L(("    elseif %s==%s then local %s=%s;%s"):format(vOP,opc(opname),va,pop_expr(),push_expr(vBIT.."."..fn_name.."("..va..")")))
end

arith("ADD","+"); arith("SUB","-"); arith("MUL","*"); arith("DIV","/")
arith("MOD","%"); arith("POW","^")
do
  local va=V(); local vb=V()
  L(("    elseif %s==%s then local %s=%s;local %s=%s;%s"):format(
    vOP,opc("IDIV"),vb,pop_expr(),va,pop_expr(),push_expr("math.floor("..va.."/"..vb..")")))
end
arith_fn("BAND","band"); arith_fn("BOR","bor"); arith_fn("BXOR","bxor")
-- ★ FIX: shl/shr のメソッド名を lshift/rshift に修正 (bit32 標準名)
arith_fn("SHL","lshift"); arith_fn("SHR","rshift")
arith("CONCAT","..")

local function unary(opname, op_sym)
  local va=V()
  L(("    elseif %s==%s then local %s=%s;%s"):format(vOP,opc(opname),va,pop_expr(),push_expr(op_sym..va)))
end
unary("UNM","-"); unary("NOT","not "); unary("LEN","#")
unary_fn("BNOT","bnot")

local function cmp(opname, op_sym)
  local va=V(); local vb=V()
  L(("    elseif %s==%s then local %s=%s;local %s=%s;%s"):format(
    vOP,opc(opname),vb,pop_expr(),va,pop_expr(),push_expr("("..va..op_sym..vb..")")))
end
cmp("EQ","=="); cmp("NEQ","~="); cmp("LT","<"); cmp("GT",">");
cmp("LEQ","<="); cmp("GEQ",">=")

local vajmp=V()
L(("    elseif %s==%s then local %s=%s;if not %s then %s=%s+%s;%s else %s end"):format(
  vOP,opc("AND_JMP"),vajmp,top_expr(),vajmp,vPC,vPC,vAR,push_expr(vajmp),pop_expr()))
local vojmp=V()
L(("    elseif %s==%s then local %s=%s;if %s then %s=%s+%s;%s else %s end"):format(
  vOP,opc("OR_JMP"),vojmp,top_expr(),vojmp,vPC,vPC,vAR,push_expr(vojmp),pop_expr()))
L(("    elseif %s==%s then %s=%s+%s"):format(vOP,opc("JMP"),vPC,vPC,vAR))
local vjf=V()
L(("    elseif %s==%s then local %s=%s;if not %s then %s=%s+%s end"):format(
  vOP,opc("JMP_FALSE"),vjf,pop_expr(),vjf,vPC,vPC,vAR))
local vjt=V()
L(("    elseif %s==%s then local %s=%s;if %s then %s=%s+%s end"):format(
  vOP,opc("JMP_TRUE"),vjt,pop_expr(),vjt,vPC,vPC,vAR))

local vfn=V(); local vargs=V(); local vres=V(); local vci=V()
L(("    elseif %s==%s then"):format(vOP,opc("CALL")))
L(("      local %s={}"):format(vargs))
L(("      for %s=1,%s do table.insert(%s,1,%s) end"):format(vci,vAR,vargs,pop_expr()))
L(("      local %s=%s"):format(vfn,pop_expr()))
L(("      local %s=_pack(%s(_unpack(%s)))"):format(vres,vfn,vargs))
-- FIX: 呼び出し結果を複数値そのままpushしていたため、CALLの結果を式の途中で
-- 使う場合(例: print(ipairs(t)) の内側呼び出し)に、外側の命令のnargsカウントと
-- 実際に積まれた値の数がズレてスタックが崩壊するバグがあった。
-- このVMは「1つの式=1つのスタック値」という前提で命令のarg(個数)を決めているため、
-- 呼び出し結果は常に先頭の戻り値1個だけをpushする(Luaの「非末尾式は1値に切り詰め」
-- 仕様に相当)。複数戻り値をそのまま使いたい場合(a,b=f() 等)は別途対応が必要。
L(("      %s"):format(push_expr(vres.."[1]")))

-- FIX: CALL_MULTI — CALLと同じ呼び出し処理だが、戻り値をすべてpushする。
-- generic forの `in` 節 (例: in ipairs(t) do) のように、Lua仕様で多値展開が
-- 必要な場面でのみパーサーがCALLをこれに差し替えて使う。
local vfn2=V(); local vargs2=V(); local vres2=V(); local vci2=V()
L(("    elseif %s==%s then"):format(vOP,opc("CALL_MULTI")))
L(("      local %s={}"):format(vargs2))
L(("      for %s=1,%s do table.insert(%s,1,%s) end"):format(vci2,vAR,vargs2,pop_expr()))
L(("      local %s=%s"):format(vfn2,pop_expr()))
L(("      local %s=_pack(%s(_unpack(%s)))"):format(vres2,vfn2,vargs2))
-- FIX: 戻り値にnilが含まれていても正しくpushできるよう、nilの代わりに番兵値を積む。
L(("      for %s=1,%s.n do local _v=%s[%s]; %s end"):format(
  vci2,vres2,vres2,vci2, push_expr("(_v==nil and "..vNILSENT.." or _v)")))
L(("      %s=%s.n"):format(vLASTMULTI,vres2))

local vrv=V(); local vri=V()
L(("    elseif %s==%s then"):format(vOP,opc("RETURN")))
L(("      local %s={}"):format(vrv))
L(("      for %s=1,%s do table.insert(%s,1,%s) end"):format(vri,vAR,vrv,pop_expr()))
-- FIX: _unpack(t) は既定で #t を使うため、戻り値の末尾にnilが含まれる場合
-- (例: return a, nil) に切り詰められてしまう。個数はコンパイル時に既知(vAR)
-- なので、それを明示してunpackする。
L(("      return _unpack(%s,1,%s)"):format(vrv,vAR))

-- FIX: RETURN_MULTI — `return f()` のように最後の式が呼び出しで終わる場合、
-- Lua仕様上fの全戻り値がそのまま返される。arg=最後の式より前にある固定個数の式の数。
-- スタックに残っている全要素(固定値+CALL_MULTIが積んだ複数値)をpopし、
-- 番兵をnilへ変換してから返す。
local vrmv=V(); local vrmn=V(); local vrmi=V()
L(("    elseif %s==%s then"):format(vOP,opc("RETURN_MULTI")))
L(("      local %s=#%s"):format(vrmn,vST))
L(("      local %s={}"):format(vrmv))
L(("      for %s=1,%s do table.insert(%s,1,%s) end"):format(vrmi,vrmn,vrmv,pop_expr()))
L(("      return _unpack(%s,1,%s)"):format(vrmv,vrmn))

-- FIX: CALL_VARARG_TAIL — 呼び出し引数リストの最後が関数呼び出しで終わる場合
-- (例: sum(table.unpack(t)) や f(a, g()))、Lua仕様上その呼び出しの全戻り値が
-- 引数として展開される。
-- 重要: RETURN_MULTIと違い、この命令は式の"途中"で実行されるため、スタックには
-- 呼び出し対象の関数や、さらに外側の式の値がこの呼び出しの引数より下に残っている
-- 可能性がある。よって「スタック全体」を使うのは不正。正しくは、直前の
-- CALL_MULTI/PUSH_VARARGが実際に何個pushしたかを記録するvLASTMULTIと、
-- 命令のarg(=末尾呼び出しより前にある固定引数の個数)を使って、必要な分だけを
-- 正確にpopする(SETLIST_MULTIと同じ手法)。
local vcvtn=V(); local vcvtv=V(); local vcvti=V(); local vcvtfn=V(); local vcvtres=V(); local vcvtfixed=V()
L(("    elseif %s==%s then"):format(vOP,opc("CALL_VARARG_TAIL")))
L(("      local %s={}"):format(vcvtv))
-- pop the trailing call's contributed values first (vLASTMULTI of them; topmost on stack)
L(("      for %s=1,%s do table.insert(%s,1,%s) end"):format(vcvti,vLASTMULTI,vcvtv,pop_expr()))
-- then pop the fixed arguments that preceded the trailing call
L(("      local %s=%s"):format(vcvtfixed,vAR))
L(("      for %s=1,%s do table.insert(%s,1,%s) end"):format(vcvti,vcvtfixed,vcvtv,pop_expr()))
L(("      local %s=%s"):format(vcvtfn,pop_expr()))
L(("      local %s=_pack(%s(_unpack(%s)))"):format(vcvtres,vcvtfn,vcvtv))
L(("      %s"):format(push_expr(vcvtres.."[1]")))

-- FIX: CALL_VARARG_TAIL_MULTI — CALL_VARARG_TAILと同じ引数収集ロジックだが、
-- この呼び出し自体がさらに外側の呼び出しの末尾可変引数として使われる場合
-- (例: print(sum(table.unpack(t))) の sum(...) 部分)、CALL同様に1値だけを
-- pushしてvLASTMULTIを更新しないと、外側がCALL_MULTIへ差し替えても正しい
-- 個数の値を受け取れない。CALL/CALL_MULTIの関係と同様に、こちらは全戻り値を
-- pushしvLASTMULTIを正しく更新する。
local vcvtn2=V(); local vcvtv2=V(); local vcvti2=V(); local vcvtfn2=V(); local vcvtres2=V(); local vcvtfixed2=V()
L(("    elseif %s==%s then"):format(vOP,opc("CALL_VARARG_TAIL_MULTI")))
L(("      local %s={}"):format(vcvtv2))
L(("      for %s=1,%s do table.insert(%s,1,%s) end"):format(vcvti2,vLASTMULTI,vcvtv2,pop_expr()))
L(("      local %s=%s"):format(vcvtfixed2,vAR))
L(("      for %s=1,%s do table.insert(%s,1,%s) end"):format(vcvti2,vcvtfixed2,vcvtv2,pop_expr()))
L(("      local %s=%s"):format(vcvtfn2,pop_expr()))
L(("      local %s=_pack(%s(_unpack(%s)))"):format(vcvtres2,vcvtfn2,vcvtv2))
L(("      for %s=1,%s.n do %s end"):format(vcvti2,vcvtres2,push_expr("(function() local _v="..vcvtres2.."["..vcvti2.."]; return (_v==nil and "..vNILSENT.." or _v) end)()")))
L(("      %s=%s.n"):format(vLASTMULTI,vcvtres2))

local vcls=V(); local vcenv=V()
L(("    elseif %s==%s then"):format(vOP,opc("CLOSURE")))
L(("      local %s=%s.f[%s]"):format(vcls,vF,vAR))
L(("      local %s=%s"):format(vcenv,vEN))
-- FIX: クロージャ生成時点のスコープチェーン(vSCOPE、外側のローカル変数を含む)を
-- コピーしてキャプチャし、子関数が呼ばれるたびにそのコピーを子VMの第4引数として
-- 渡す。これにより inner関数が outer関数のローカル変数(upvalue)を参照できる。
-- (テーブルそのものではなく浅いコピーを都度渡すのは、複数回の呼び出し間で
--  子VMが自分のスコープを積み増しても親のキャプチャ済みチェーンを汚染しない
--  ようにするため)
L(("      local %s={}"):format("_capScope"))
L(("      for _csi=1,#%s do %s[_csi]=%s[_csi] end"):format(vSCOPE,"_capScope",vSCOPE))
L(("      %s"):format(push_expr("(function(...) local _fa={...}; local _cs={}; for _i=1,#_capScope do _cs[_i]=_capScope[_i] end; return "..vVM.."("..vcls..",_fa,"..vcenv..",_cs) end)")))

L(("    elseif %s==%s then %s[#%s+1]={}"):format(vOP,opc("ENTER_SCOPE"),vSCOPE,vSCOPE))
L(("    elseif %s==%s then %s[#%s]=nil"):format(vOP,opc("LEAVE_SCOPE"),vSCOPE,vSCOPE))

local vfp_st=V(); local vfp_lim=V(); local vfp_stp=V()
L(("    elseif %s==%s then"):format(vOP,opc("FORPREP")))
L(("      local %s=%s;local %s=%s;local %s=%s"):format(vfp_stp,pop_expr(),vfp_lim,pop_expr(),vfp_st,pop_expr()))
L(("      %s[#%s+1]={%s,%s,%s}"):format(vNFOR,vNFOR,vfp_st,vfp_lim,vfp_stp))
L(("      if (%s>0 and %s>%s) or (%s<=0 and %s<%s) then %s=%s+%s end"):format(
  vfp_stp,vfp_st,vfp_lim, vfp_stp,vfp_st,vfp_lim, vPC,vPC,vAR))
local vfl_fr=V()
L(("    elseif %s==%s then"):format(vOP,opc("FORLOOP")))
L(("      local %s=%s[#%s]"):format(vfl_fr,vNFOR,vNFOR))
L(("      %s[1]=%s[1]+%s[3]"):format(vfl_fr,vfl_fr,vfl_fr))
L(("      if (%s[3]>0 and %s[1]<=%s[2]) or (%s[3]<=0 and %s[1]>=%s[2]) then %s=%s+%s"):format(
  vfl_fr,vfl_fr,vfl_fr, vfl_fr,vfl_fr,vfl_fr, vPC,vPC,vAR))
L(("      else %s[#%s]=nil end"):format(vNFOR,vNFOR))

-- FIX: BIND_FORVAR — 専用フレームスタック vNFOR の一番上のフレームから
-- 現在値(st)を取り出し、ループ変数名でローカルスコープにSET_LOCALする。
-- 式評価用スタック(ST)とは分離しているため本体内の演算で破壊されない。
L(("    elseif %s==%s then local %s=%s[#%s][1];%s(_N[%s],%s)"):format(
  vOP,opc("BIND_FORVAR"),"_bfv",vNFOR,vNFOR,vSET_L,vAR,"_bfv"))
-- FIX: BIND_GFORVARS — 専用フレームスタック vGFOR の一番上のフレームに保存された
-- results配列から、呼ばれた順に1個ずつ取り出して対応する変数名にSET_LOCALする。
-- (parseStat側で names を逆順にemitしているので、実行順は names[1],names[2],... となり
--  results[1],results[2],...と正しく対応する)
local vgv_fr=V()
L(("    elseif %s==%s then"):format(vOP,opc("BIND_GFORVARS")))
L(("      local %s=%s[#%s]"):format(vgv_fr,vGFOR,vGFOR))
L(("      %s.ri=(%s.ri or 0)+1"):format(vgv_fr,vgv_fr))
L(("      %s(_N[%s],%s.results[%s.ri])"):format(vSET_L,vAR,vgv_fr,vgv_fr))

local vgfp_c=V(); local vgfp_s=V(); local vgfp_i=V(); local vgfp_r=V()
L(("    elseif %s==%s then"):format(vOP,opc("GFORPREP")))
L(("      local %s=%s;local %s=%s;local %s=%s"):format(vgfp_c,pop_expr(),vgfp_s,pop_expr(),vgfp_i,pop_expr()))
-- vgfp_c=初期control値, vgfp_s=state, vgfp_i=iterator関数 (parseExprList評価順 f,s,var の逆popなので)
-- FIX: GFORPREPはフレームを積むだけで初回のイテレータ呼び出しをしていなかったため、
-- 直後のBIND_GFORVARSが空のresultsを参照してnilを束縛してしまうバグがあった。
-- ここで最初の呼び出し f(s,c) を行い、resultsを埋めてから本体へ入る。
-- (呼び出し結果がnilなら最初からループ0回、GFORLOOPまで到達しないよう
--  arg(ジャンプ先=GFORLOOPの次)へ飛ばす)
L(("      local %s={%s(%s,%s)}"):format(vgfp_r,vgfp_i,vgfp_s,vgfp_c))
L(("      if %s[1]==nil then"):format(vgfp_r))
L(("        %s=%s+%s"):format(vPC,vPC,vAR))
L("      else")
L(("        %s[#%s+1]={f=%s,s=%s,c=%s[1],results=%s,ri=0}"):format(vGFOR,vGFOR,vgfp_i,vgfp_s,vgfp_r,vgfp_r))
L("      end")

-- FIX: GFORLOOP — 専用フレームスタック(vGFOR)を使い、式評価用スタック(ST)を汚さない。
-- イテレータ関数を呼び、結果が nil でなければ次周のcontrol値を更新してresultsを保存、
-- BIND_GFORVARSが順に取り出せるようにする。
local vgfl_fr=V(); local vgfl_r=V()
L(("    elseif %s==%s then"):format(vOP,opc("GFORLOOP")))
L(("      local %s=%s[#%s]"):format(vgfl_fr,vGFOR,vGFOR))
L(("      local %s={%s.f(%s.s,%s.c)}"):format(vgfl_r,vgfl_fr,vgfl_fr,vgfl_fr))
L(("      if %s[1]~=nil then"):format(vgfl_r))
L(("        %s.c=%s[1];%s.results=%s;%s.ri=0"):format(vgfl_fr,vgfl_r,vgfl_fr,vgfl_r,vgfl_fr))
L(("        %s=%s+%s"):format(vPC,vPC,vAR))
L("      else")
L(("        %s[#%s]=nil"):format(vGFOR,vGFOR))
L("      end")

-- ════════════════════════════════════════════════════
-- 複合命令ハンドラ (ChatGPT指摘1: 1opcode≠1操作 の実装)
-- ════════════════════════════════════════════════════

-- GCALL: PUSH_GLOBAL[name_idx] + CALL[0] の融合（引数なし呼び出し専用）
-- arg = name_idx
do
  local vGC_fn=V(); local vGC_r=V()
  L(("    elseif %s==%s then"):format(vOP,opc("GCALL")))
  L(("      local %s=%s[_N[%s]]"):format(vGC_fn, vEN, vAR))
  L(("      local %s=_pack(%s())"):format(vGC_r, vGC_fn))
  L(("      %s[#%s+1]=%s[1]"):format(vST, vST, vGC_r))
end

-- PUSH_IMM: 即値整数を定数テーブルなしで直接push
-- arg = value + 16384 (オフセット付き符号なし)
do
  L(("    elseif %s==%s then %s"):format(vOP, opc("PUSH_IMM"), push_expr(("(%s-16384)"):format(vAR))))
end

-- NUMOP: 算術演算の統合命令
-- arg = 演算種別 (0=ADD,1=SUB,2=MUL,3=DIV,4=MOD,5=POW,6=IDIV,7=CONCAT)
do
  local vNA=V(); local vNB=V(); local vNK=V()
  local bit_helper = ("(function(a,b) local r=0;for i=0,7 do if math.floor(a/2^i)%%2~=math.floor(b/2^i)%%2 then r=r+2^i end end;return r end)"):format()
  L(("    elseif %s==%s then"):format(vOP, opc("NUMOP")))
  L(("      local %s=%s;local %s=%s"):format(vNB, pop_expr(), vNA, pop_expr()))
  L(("      local %s=%s"):format(vNK, vAR))
  L(("      if %s==0 then %s"):format(vNK, push_expr(vNA.."+"..vNB)))
  L(("      elseif %s==1 then %s"):format(vNK, push_expr(vNA.."-"..vNB)))
  L(("      elseif %s==2 then %s"):format(vNK, push_expr(vNA.."*"..vNB)))
  L(("      elseif %s==3 then %s"):format(vNK, push_expr(vNA.."/"..vNB)))
  L(("      elseif %s==4 then %s"):format(vNK, push_expr(vNA.."%"..vNB)))
  L(("      elseif %s==5 then %s"):format(vNK, push_expr(vNA.."^"..vNB)))
  L(("      elseif %s==6 then %s"):format(vNK, push_expr("math.floor("..vNA.."/"..vNB..")")))
  L(("      else %s end"):format(push_expr(("tostring(%s)..tostring(%s)"):format(vNA,vNB))))
end

-- GSET_TOP: スタックトップを GLOBAL[arg] に代入して pop (SET_GLOBAL+POP 融合)
do
  local vGST_v=V()
  L(("    elseif %s==%s then local %s=%s;%s[_N[%s]]=%s"):format(
    vOP, opc("GSET_TOP"), vGST_v, pop_expr(), vEN, vAR, vGST_v))
end

-- HARDENING: ディスパッチチェーンの終端。DISPATCH_BLOCK_START からここまでの
-- 行が、シャッフル対象の elseif ブロック群。
local DISPATCH_BLOCK_END = #lines

L("    end")
L("  end")
L("end")

local vEntry=V()
L(("local %s=function()"):format(vEntry))
L(("  %s(%s,{},_G,{})"):format(vVM,vPR))
L("end")
L(("%s()"):format(vEntry))
L("end)()")

-- HARDENING (CFF強化): ディスパッチハンドラを単純な1本のif/elseif鎖で並べる
-- のではなく、各Opcodeが所属するバンド(band)ごとにグループ化し、
--   外側: vOPの数値レンジ判定で「どのバンドか」を粗く振り分け (安価なレンジ比較)
--   内側: バンド内のOpcodeに対してのみ個別の厳密一致判定を行う
-- という2階層のネスト構造に再構築する。strength(1〜15)に応じてバンド数
-- (DISPATCH_BAND_COUNT)が増減するため、strengthが高いほど木構造が深く・
-- 枝分かれが多くなり、CFGの複雑さ(基本ブロック数・分岐数・ネスト深さ)が
-- 大幅に増加する。各ハンドラ内部の実行ロジック自体は一切変更しないため、
-- 挙動は完全に保たれる。
do
  local blockStartPattern = "^%s*e?lseif%s+"..vOP.."=="
  local blockStartPatternIf = "^%s*if%s+"..vOP.."=="
  local function isBlockStart(ln) return ln:match(blockStartPattern) or ln:match(blockStartPatternIf) end
  local blocks = {}
  local cur = nil
  for i=DISPATCH_BLOCK_START,DISPATCH_BLOCK_END do
    local ln = lines[i]
    if isBlockStart(ln) then
      if cur then blocks[#blocks+1]=cur end
      cur = {ln}
    else
      if cur then cur[#cur+1]=ln
      else
        -- Shouldn't happen (first line in range must be a block start), but
        -- guard against it just in case by starting an implicit block.
        cur = {ln}
      end
    end
  end
  if cur then blocks[#blocks+1]=cur end

  -- 実ブロックの数とopc()呼び出し回数が一致する場合のみ、呼び出し順
  -- (=opcCallOrder)から各ブロックの実際の比較値(vOP==の右辺、すなわち
  -- 生のOP[name]、1..MAX_OPの範囲)を正確に求める。
  -- 注意: ディスパッチ時のvOPは、パック済みバイトコードに埋め込まれた
  -- シャッフル済みop2c値を vUM(=buildShardedResolver()の逆引き)で
  -- 復元した「生のOpcode番号」であり、op2c/opBand(バイトコード自体の
  -- 難読化用)とは別の数値空間である。そのため階層化の範囲分けは
  -- OP[name](1..MAX_OP)の値そのものを直接使う必要がある。
  -- 万一呼び出し回数が一致しない場合は安全側に倒し、全ブロックを
  -- 単一チェーンにまとめる(=従来のフラットな挙動にフォールバックし、
  -- 壊れた構造を生成しない)。
  local realCount = #blocks
  local blockVal = {}
  local mappingOk = (#opcCallOrder == realCount)
  if mappingOk then
    for i=1,realCount do
      local rawOp = OP[opcCallOrder[i]]
      if not rawOp then mappingOk=false; break end
      blockVal[i] = rawOp
    end
  end

  -- HARDENING: デコイ(実行されない偽)ハンドラブロックを混入する。
  -- 比較値は実在するop2c値(c2opに登録済みの値)とも、実在する生Opcode値
  -- (1..MAX_OP)とも重複しないことを保証した上でランダムに選ぶため、実行時に
  -- 絶対にマッチせず完全なデッドコードだが、構造的には本物のハンドラと
  -- 見分けがつかない(同じ "if/elseif <vOP>==<num> then <本体>" の形)。
  -- 本体は既存のオペコード実装パターンを模した無害などこにも影響しない
  -- ローカル変数操作にする。
  -- strength(1〜15)に応じてデコイ分岐数をスケーリング（strength=5で従来値(8,16)相当）
  local DECOY_MAX = math.max(8, math.floor(8 + strength*1.6))
  local DECOY_COUNT = math.random(8, DECOY_MAX)
  local DECOY_BASE = MAX_OP + 1000
  for _=1,DECOY_COUNT do
    local decoyVal
    repeat decoyVal = DECOY_BASE + math.random(1, 900000) until not c2op[decoyVal]
    local pattern = math.random(1,4)
    local decoyLines = {}
    local vTmp1, vTmp2, vTmp3 = V(), V(), V()
    if pattern==1 then
      decoyLines[1] = ("    elseif %s==%s then local %s=%s;%s=%s+%s"):format(
        vOP, ne(decoyVal), vTmp1, top_expr(), vPC, vPC, ne(math.random(1,9)))
    elseif pattern==2 then
      decoyLines[1] = ("    elseif %s==%s then"):format(vOP, ne(decoyVal))
      decoyLines[2] = ("      local %s={}"):format(vTmp1)
      decoyLines[3] = ("      for %s=1,%s do %s[%s]=%s end"):format(vTmp2, ne(math.random(1,5)), vTmp1, vTmp2, ne(math.random(0,999)))
      decoyLines[4] = ("      %s=#%s"):format(vTmp3, vTmp1)
    elseif pattern==3 then
      decoyLines[1] = ("    elseif %s==%s then local %s=%s;local %s=%s;if %s then %s=%s+%s end"):format(
        vOP, ne(decoyVal), vTmp1, pop_expr(), vTmp2, pop_expr(), vTmp1, vPC, vPC, ne(math.random(1,20)))
    else
      decoyLines[1] = ("    elseif %s==%s then"):format(vOP, ne(decoyVal))
      decoyLines[2] = ("      local %s=%s"):format(vTmp1, ne(math.random(0,255)))
      decoyLines[3] = ("      local %s=%s"):format(vTmp2, ne(math.random(0,255)))
      decoyLines[4] = ("      %s=(%s+%s)%%%s"):format(vTmp3, vTmp1, vTmp2, ne(math.random(2,9)))
    end
    blocks[#blocks+1] = decoyLines
    blockVal[#blocks] = decoyVal
  end
  local totalCount = #blocks

  -- ブロック先頭行を "if" / "elseif" に正規化するヘルパー。元の行がどちらの
  -- キーワードで書かれていても対応する(シャッフルで任意の位置に来るため)。
  local function normalizeHead(firstLine, isFirst)
    local kw = isFirst and "if " or "elseif "
    local rewritten = firstLine:gsub("^(%s*)elseif%s+", "%1"..kw, 1)
    if rewritten == firstLine then
      rewritten = firstLine:gsub("^(%s*)if%s+", "%1"..kw, 1)
    end
    return rewritten
  end

  -- CFF強化(ブロック分割の粒度アップ): 値域[lo,hi]とその範囲に属するブロック
  -- 集合(items, 各要素は{val=比較値, lines=ブロック本体行})を受け取り、
  -- 再帰的に2分割しながらネストしたif/elseifディスパッチを構築する。
  --   - items数がLEAF_MAX以下、または最大深さに達したら、その場でシャッフル
  --     した上でフラットなif/elseif/endの葉(リーフ)として確定する。
  --   - そうでなければ[lo,hi]を中点で左右に分割し、各ブロックを実際の値
  --     (val)がどちら側に属するかで振り分け、両側を再帰的に構築した上で
  --     外側をレンジ判定(if vOP>=lo and vOP<=mid then ... elseif ... end)
  --     で包む。
  -- 前段(前回実装)の単純な等分割ティアを一般化したもので、同じ「値その
  -- ものでの範囲判定」という検証済みの手法を再帰適用するため、正確性は
  -- 数学的に保証される(ブロックのvalは必ずlo..hiの範囲内にあり、中点で
  -- 分けた片方に必ず属する)。strength(1〜15)に応じて最大深さを増やし、
  -- ネストの深さ・分岐の総数を大幅に増加させる。
  local MAX_DEPTH = math.min(6, math.max(1, math.floor(1 + (strength-1)/2.5)))
  local LEAF_MAX = 4
  local function buildLeaf(items)
    for i=#items,2,-1 do local j=math.random(1,i); items[i],items[j]=items[j],items[i] end
    local out = {}
    for bi,it in ipairs(items) do
      out[#out+1] = normalizeHead(it.lines[1], bi==1)
      for k=2,#it.lines do out[#out+1]=it.lines[k] end
    end
    out[#out+1] = "      end"
    return out
  end
  local function buildRangeDispatch(items, lo, hi, depth)
    if #items<=LEAF_MAX or depth>=MAX_DEPTH or hi<=lo then
      return buildLeaf(items)
    end
    local mid = lo + math.floor((hi-lo)/2)
    local leftItems, rightItems = {}, {}
    for _,it in ipairs(items) do
      if it.val<=mid then leftItems[#leftItems+1]=it else rightItems[#rightItems+1]=it end
    end
    -- 分割しても片側に全て偏った場合(境界の取り方次第であり得る)は、
    -- 無限再帰を避けるためその場でリーフ化する。
    if #leftItems==0 or #rightItems==0 then
      return buildLeaf(items)
    end
    local branches = {
      {lo=lo, hi=mid, items=leftItems},
      {lo=mid+1, hi=hi, items=rightItems},
    }
    local out = {}
    for idx,br in ipairs(branches) do
      local kw = (idx==1) and "      if " or "      elseif "
      out[#out+1] = ("%s%s>=%s and %s<=%s then"):format(kw, vOP, ne(br.lo), vOP, ne(br.hi))
      local inner = buildRangeDispatch(br.items, br.lo, br.hi, depth+1)
      for _,ln in ipairs(inner) do out[#out+1]=ln end
    end
    out[#out+1] = "      end"
    return out
  end

  -- 実Opcode用ドメイン[1,MAX_OP]とデコイ用ドメイン[DECOY_BASE+1, 999999999]
  -- の2つに分け、それぞれ独立に再帰ディスパッチ木を構築する。
  -- マッピングに失敗した場合(mappingOk=false)は安全側に倒し、全ブロックを
  -- 1つの巨大なレンジ[1,999999999]でまとめて1つの木として構築する
  -- (=従来のフラットな挙動と等価、壊れた構造を生成しない)。
  local outer = {}
  if not mappingOk then
    local allItems = {}
    for i=1,totalCount do allItems[#allItems+1] = {val=blockVal[i] or 1, lines=blocks[i]} end
    outer[#outer+1] = ("    if %s>=%s and %s<=%s then"):format(vOP, ne(1), vOP, ne(999999999))
    local tree = buildRangeDispatch(allItems, 1, 999999999, 0)
    for _,ln in ipairs(tree) do outer[#outer+1]=ln end
  else
    local realItems, decoyItems = {}, {}
    for i=1,totalCount do
      local it = {val=blockVal[i], lines=blocks[i]}
      if blockVal[i] <= MAX_OP then realItems[#realItems+1]=it
      else decoyItems[#decoyItems+1]=it end
    end
    local domains = {}
    if #realItems>0 then domains[#domains+1] = {lo=1, hi=MAX_OP, items=realItems} end
    if #decoyItems>0 then domains[#domains+1] = {lo=DECOY_BASE+1, hi=999999999, items=decoyItems} end
    for idx,d in ipairs(domains) do
      local kw = (idx==1) and "    if " or "    elseif "
      outer[#outer+1] = ("%s%s>=%s and %s<=%s then"):format(kw, vOP, ne(d.lo), vOP, ne(d.hi))
      local tree = buildRangeDispatch(d.items, d.lo, d.hi, 0)
      for _,ln in ipairs(tree) do outer[#outer+1]=ln end
    end
  end
  -- VM Coreハードニング: 未定義Opcode検出。どのドメイン/レンジにも一致
  -- しない値が来た場合は、意味不明な状態で実行を継続させず安全に停止する。
  outer[#outer+1] = "    else"
  outer[#outer+1] = "      error(\"VM: invalid opcode\")"
  outer[#outer+1] = "    end"

  -- Splice the rebuilt nested dispatch back into the original `lines` array,
  -- replacing DISPATCH_BLOCK_START..(DISPATCH_BLOCK_END+1): the "+1" absorbs
  -- the original flat chain's closing "    end" (index DISPATCH_BLOCK_END+1),
  -- since the new nested structure supplies its own closing "end" lines.
  local newLines = {}
  for i=1,DISPATCH_BLOCK_START-1 do newLines[#newLines+1]=lines[i] end
  for _,ln in ipairs(outer) do newLines[#newLines+1]=ln end
  for i=DISPATCH_BLOCK_END+2,#lines do newLines[#newLines+1]=lines[i] end
  lines = newLines

end

local final=table.concat(lines,"\n")
local fw=io.open(output_file,"w")
if not fw then die("cannot write: "..output_file) end
fw:write(final); fw:close()
io.stderr:write("VM_OBF_INFO: done! "..output_file.."\n")
io.write("OK:"..output_file)
