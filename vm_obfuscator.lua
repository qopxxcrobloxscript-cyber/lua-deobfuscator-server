--[[
  YAJU True VM Obfuscator v4.0 - 完全自前実装
  luac不要。Luaソースを直接パース→独自VM命令列に変換→難読化VMを生成。

  フロー:
    1. Lexer: ソースをトークン列に変換
    2. Parser: トークン列をASTに変換
    3. Compiler: ASTを独自VM命令列にコンパイル
    4. Shuffler: シード依存でopcodeをシャッフル
    5. Emitter: 難読化済みLuaコード（自前VMインタープリタ付き）を出力
]]

-- ═══════════════════════════════════════════════
--  ユーティリティ
-- ═══════════════════════════════════════════════
local function die(msg)
  io.stderr:write("VM_OBF_ERROR: " .. tostring(msg) .. "\n")
  os.exit(1)
end

local args = {...}
local input_file, output_file = nil, nil
local seed = math.random(100000, 999999)
do
  local i = 1
  while i <= #args do
    if args[i]=="--out" and args[i+1] then i=i+1; output_file=args[i]
    elseif args[i]=="--seed" and args[i+1] then i=i+1; seed=tonumber(args[i]) or seed
    elseif not input_file then input_file=args[i]
    end
    i=i+1
  end
end
if not input_file then die("usage: lua vm_obfuscator.lua input.lua --out out.lua") end
if not output_file then output_file=input_file:gsub("%.lua$","").."_vm.lua" end

local fh = io.open(input_file,"r")
if not fh then die("cannot open: "..input_file) end
local source = fh:read("*a"); fh:close()
if not source or #source==0 then die("empty input") end

-- ═══════════════════════════════════════════════
--  PRNG / 変数名生成 / 数値難読化
-- ═══════════════════════════════════════════════
local rng_s = seed
local function rng()
  rng_s=(rng_s*1664525+1013904223)%4294967296; return rng_s
end
local used_v={}
local function V()
  local conf={"I","l","O","Il","lI","IO","OI","lO","Ol"}
  local fill={"I","l","O","_","1","0"}
  local n
  repeat
    n=conf[(rng()%#conf)+1]
    for _=1,8+(rng()%5) do n=n..fill[(rng()%#fill)+1] end
  until not used_v[n]
  used_v[n]=true; return n
end
local function ne(n)
  if type(n)~="number" then return tostring(n) end
  n=math.floor(n)
  if n==0 then return "0" end
  local r=rng()%3
  if r==0 then local a=(rng()%40)+2;local b=math.floor(n/a);local c=n-a*b;return("(%d*%d+%d)"):format(a,b,c)
  elseif r==1 then local o=(rng()%80)+5;return("(%d-%d)"):format(n+o,o)
  else local f=(rng()%6)+2;local q=math.floor(n/f);local c=n-f*q;return("(%d*%d+%d)"):format(f,q,c) end
end
local function hide_str(s)
  local key=(rng()%50)+3
  local enc={}
  for i=1,#s do enc[i]=ne((s:byte(i)+key+(i%5)*2)%256) end
  local vt,vr,vi=V(),V(),V()
  return("(function()local %s={%s};local %s={};for %s=1,#%s do %s[%s]=string.char((%s[%s]-%d-(%s-1)%%5*2+512)%%256)end;return table.concat(%s)end)()"):format(
    vt,table.concat(enc,","),vr,vi,vt,vr,vi,vt,vi,key,vi,vr)
end

-- ═══════════════════════════════════════════════
--  LEXER
-- ═══════════════════════════════════════════════
local TK = {
  -- リテラル
  NUMBER="NUMBER", STRING="STRING", NAME="NAME", EOF="EOF",
  -- キーワード
  AND="and",BREAK="break",DO="do",ELSE="else",ELSEIF="elseif",
  END="end",FALSE="false",FOR="for",FUNCTION="function",GOTO="goto",
  IF="if",IN="in",LOCAL="local",NIL="nil",NOT="not",
  OR="or",REPEAT="repeat",RETURN="return",THEN="then",TRUE="true",
  UNTIL="until",WHILE="while",
  -- 記号
  PLUS="+",MINUS="-",STAR="*",SLASH="/",PERCENT="%",CARET="^",HASH="#",
  AMPERSAND="&",TILDE="~",PIPE="|",LSHIFT="<<",RSHIFT=">>",DSLASH="//",
  EQ="==",NEQ="~=",LT="<",GT=">",LEQ="<=",GEQ=">=",
  ASSIGN="=",LPAREN="(",RPAREN=")",LBRACE="{",RBRACE="}",LBRACKET="[",RBRACKET="]",
  DCOLON="::",SEMICOLON=";",COLON=":",COMMA=",",DOT=".",CONCAT="..",DOTS="...",
}
local KEYWORDS={}
for _,k in ipairs({"and","break","do","else","elseif","end","false","for",
  "function","goto","if","in","local","nil","not","or","repeat","return",
  "then","true","until","while"}) do KEYWORDS[k]=k end

local function Lexer(src)
  local self={src=src,pos=1,line=1,tokens={},ti=1}

  local function peek(n) return self.src:sub(self.pos,self.pos+(n or 1)-1) end
  local function advance(n) local s=peek(n);self.pos=self.pos+(n or 1);return s end
  local function cur() return self.src:sub(self.pos,self.pos) end

  local function skipWhitespaceAndComments()
    while self.pos<=#self.src do
      local c=cur()
      if c==" " or c=="\t" or c=="\r" then advance()
      elseif c=="\n" then advance();self.line=self.line+1
      elseif c=="-" and peek(2)=="--" then
        advance(2)
        if cur()=="[" then
          local lvl=0; local p2=self.pos+1
          while self.src:sub(p2,p2)=="=" do lvl=lvl+1;p2=p2+1 end
          if self.src:sub(p2,p2)=="[" then
            self.pos=p2+1
            local close="]"..string.rep("=",lvl).."]"
            local e=self.src:find(close,self.pos,true)
            if e then self.pos=e+#close else self.pos=#self.src+1 end
          else
            local e=self.src:find("\n",self.pos,true)
            self.pos=e and e+1 or #self.src+1
          end
        else
          local e=self.src:find("\n",self.pos,true)
          self.pos=e and e+1 or #self.src+1
        end
      else break end
    end
  end

  local function readLongString()
    -- '[' already consumed, check '='* '['
    local lvl=0
    while cur()=="=" do lvl=lvl+1;advance() end
    if cur()~="[" then return nil end
    advance()
    local close="]"..string.rep("=",lvl).."]"
    -- skip immediate newline
    if cur()=="\n" then advance();self.line=self.line+1
    elseif peek(2)=="\r\n" then advance(2);self.line=self.line+1 end
    local buf={}
    while self.pos<=#self.src do
      if self.src:sub(self.pos,self.pos+#close-1)==close then
        self.pos=self.pos+#close
        return table.concat(buf)
      end
      local c=advance()
      if c=="\n" then self.line=self.line+1 end
      buf[#buf+1]=c
    end
    die("unfinished long string")
  end

  local function readString(q)
    advance() -- skip quote
    local buf={}
    while self.pos<=#self.src do
      local c=cur()
      if c==q then advance();return table.concat(buf) end
      if c=="\n" or c=="\r" then die("unfinished string line "..self.line) end
      if c=="\\" then
        advance()
        local e=cur(); advance()
        if     e=="n"  then buf[#buf+1]="\n"
        elseif e=="t"  then buf[#buf+1]="\t"
        elseif e=="r"  then buf[#buf+1]="\r"
        elseif e=="\\" then buf[#buf+1]="\\"
        elseif e=="'"  then buf[#buf+1]="'"
        elseif e=='"'  then buf[#buf+1]='"'
        elseif e=="0"  then buf[#buf+1]="\0"
        elseif e=="x"  then
          local h=advance(2)
          buf[#buf+1]=string.char(tonumber(h,16) or 0)
        elseif e>="0" and e<="9" then
          local ds=e
          if cur()>="0" and cur()<="9" then ds=ds..advance() end
          if cur()>="0" and cur()<="9" then ds=ds..advance() end
          buf[#buf+1]=string.char(tonumber(ds) or 0)
        elseif e=="\n" then buf[#buf+1]="\n";self.line=self.line+1
        else buf[#buf+1]=e end
      else buf[#buf+1]=c;advance() end
    end
    die("unfinished string")
  end

  local function readNumber()
    local start=self.pos
    if peek(2)=="0x" or peek(2)=="0X" then
      advance(2)
      while cur():match("[0-9a-fA-F_]") do advance() end
    else
      while cur():match("[0-9]") do advance() end
      if cur()=="." then
        advance()
        while cur():match("[0-9]") do advance() end
      end
      if cur():match("[eE]") then
        advance()
        if cur():match("[+-]") then advance() end
        while cur():match("[0-9]") do advance() end
      end
    end
    return tonumber(self.src:sub(start,self.pos-1))
  end

  function self:tokenize()
    while true do
      skipWhitespaceAndComments()
      if self.pos>#self.src then self.tokens[#self.tokens+1]={type=TK.EOF,line=self.line};break end
      local c=cur()
      local line=self.line

      -- long string
      if c=="[" and (self.src:sub(self.pos+1,self.pos+1)=="[" or self.src:sub(self.pos+1,self.pos+1)=="=") then
        local save=self.pos; advance()
        local s=readLongString()
        if s then self.tokens[#self.tokens+1]={type=TK.STRING,value=s,line=line}
        else self.pos=save;self.tokens[#self.tokens+1]={type=TK.LBRACKET,line=line};advance() end

      -- strings
      elseif c=='"' or c=="'" then
        self.tokens[#self.tokens+1]={type=TK.STRING,value=readString(c),line=line}

      -- numbers
      elseif c:match("[0-9]") or (c=="." and self.src:sub(self.pos+1,self.pos+1):match("[0-9]")) then
        self.tokens[#self.tokens+1]={type=TK.NUMBER,value=readNumber(),line=line}

      -- names / keywords
      elseif c:match("[a-zA-Z_]") then
        local start=self.pos
        while cur():match("[a-zA-Z0-9_]") do advance() end
        local word=self.src:sub(start,self.pos-1)
        local kw=KEYWORDS[word]
        self.tokens[#self.tokens+1]={type=kw or TK.NAME,value=word,line=line}

      -- symbols
      else
        local s2=peek(3)
        if s2=="..." then advance(3);self.tokens[#self.tokens+1]={type=TK.DOTS,line=line}
        elseif s2:sub(1,2)==".." then advance(2);self.tokens[#self.tokens+1]={type=TK.CONCAT,line=line}
        elseif s2:sub(1,2)=="==" then advance(2);self.tokens[#self.tokens+1]={type=TK.EQ,line=line}
        elseif s2:sub(1,2)=="~=" then advance(2);self.tokens[#self.tokens+1]={type=TK.NEQ,line=line}
        elseif s2:sub(1,2)=="<=" then advance(2);self.tokens[#self.tokens+1]={type=TK.LEQ,line=line}
        elseif s2:sub(1,2)==">=" then advance(2);self.tokens[#self.tokens+1]={type=TK.GEQ,line=line}
        elseif s2:sub(1,2)=="<<" then advance(2);self.tokens[#self.tokens+1]={type=TK.LSHIFT,line=line}
        elseif s2:sub(1,2)==">>" then advance(2);self.tokens[#self.tokens+1]={type=TK.RSHIFT,line=line}
        elseif s2:sub(1,2)=="//" then advance(2);self.tokens[#self.tokens+1]={type=TK.DSLASH,line=line}
        elseif s2:sub(1,2)=="::" then advance(2);self.tokens[#self.tokens+1]={type=TK.DCOLON,line=line}
        else
          local sym={
            ["+"]=TK.PLUS,["-"]=TK.MINUS,["*"]=TK.STAR,["/"]=TK.SLASH,
            ["%"]=TK.PERCENT,["^"]=TK.CARET,["#"]=TK.HASH,["&"]=TK.AMPERSAND,
            ["|"]=TK.PIPE,["~"]=TK.TILDE,["<"]=TK.LT,[">"]=TK.GT,
            ["="]=TK.ASSIGN,["("]=TK.LPAREN,[")"]=TK.RPAREN,
            ["{"]=TK.LBRACE,["}"]=TK.RBRACE,["["]=TK.LBRACKET,["]"]=TK.RBRACKET,
            [";"]=TK.SEMICOLON,[":"]=TK.COLON,[","]=TK.COMMA,["."]=TK.DOT,
          }
          if sym[c] then advance();self.tokens[#self.tokens+1]={type=sym[c],line=line}
          else advance() end -- skip unknown
        end
      end
    end
    return self.tokens
  end

  function self:peek(offset)
    return self.tokens[self.ti+(offset or 0)] or {type=TK.EOF}
  end
  function self:next()
    local t=self.tokens[self.ti] or {type=TK.EOF}
    self.ti=self.ti+1; return t
  end
  function self:check(tp) return self.tokens[self.ti] and self.tokens[self.ti].type==tp end
  function self:match(tp)
    if self:check(tp) then return self:next() end
  end
  function self:expect(tp)
    if not self:check(tp) then
      local t=self.tokens[self.ti] or {type="?"}
      die(("expected %s got %s at token %d"):format(tp,t.type,self.ti))
    end
    return self:next()
  end

  self:tokenize()
  return self
end

-- ═══════════════════════════════════════════════
--  VM 命令セット定義
-- ═══════════════════════════════════════════════
local OP = {
  -- スタック操作
  PUSH_NIL=1, PUSH_TRUE=2, PUSH_FALSE=3,
  PUSH_NUM=4,   -- arg: const_index
  PUSH_STR=5,   -- arg: const_index
  PUSH_VAR=6,   -- arg: name_index
  PUSH_GLOBAL=7,-- arg: name_index
  POP=8,
  -- 変数操作
  SET_LOCAL=9,  -- arg: name_index
  SET_GLOBAL=10,-- arg: name_index
  DEF_LOCAL=11, -- arg: name_index (local宣言)
  -- テーブル
  NEW_TABLE=12,
  GET_TABLE=13, -- stack: table, key → value
  SET_TABLE=14, -- stack: table, key, value
  GET_FIELD=15, -- arg: name_index; stack: table → value
  SET_FIELD=16, -- arg: name_index; stack: table, value
  -- 算術
  ADD=17, SUB=18, MUL=19, DIV=20, MOD=21, POW=22, IDIV=23,
  UNM=24, -- unary minus
  -- ビット演算
  BAND=25, BOR=26, BXOR=27, BNOT=28, SHL=29, SHR=30,
  -- 文字列
  CONCAT=31, LEN=32,
  -- 比較
  EQ=33, NEQ=34, LT=35, GT=36, LEQ=37, GEQ=38,
  -- 論理
  NOT=39,
  AND_JMP=40, -- short-circuit AND: if top false, jump; arg: offset
  OR_JMP=41,  -- short-circuit OR:  if top true,  jump; arg: offset
  -- ジャンプ
  JMP=42,       -- arg: offset (relative)
  JMP_FALSE=43, -- pop & jump if false; arg: offset
  JMP_TRUE=44,  -- pop & jump if true;  arg: offset
  -- 関数
  CALL=45,      -- arg: nargs (results pushed)
  RETURN=46,    -- arg: nvals (0=return nothing)
  TAILCALL=47,
  -- クロージャ
  CLOSURE=48,   -- arg: func_index
  -- ループ
  FORPREP=49,   -- arg: jump offset for exit
  FORLOOP=50,   -- arg: jump offset back
  -- ジェネリックfor
  GFORPREP=51,
  GFORLOOP=52,  -- arg: nvar, offset
  -- その他
  SETLIST=53,   -- arg: count (テーブルコンストラクタ用)
  DUP=54,       -- スタックトップを複製
  PUSH_VARARG=55,
  -- スコープ
  ENTER_SCOPE=56,
  LEAVE_SCOPE=57,
  -- 複数代入
  ADJUST=58,    -- arg: n (スタックをn個に調整)
}

-- ═══════════════════════════════════════════════
--  COMPILER (AST不要: 再帰下降で直接命令列生成)
-- ═══════════════════════════════════════════════
local function Compiler(lex)
  local self={}
  self.code={}       -- {op, arg}
  self.consts={}     -- 定数プール
  self.const_idx={}  -- 値→インデックス
  self.names={}      -- 名前プール
  self.name_idx={}
  self.funcs={}      -- サブ関数リスト
  self.locals={}     -- ローカル変数スタック (スコープ対応)
  self.scope={}      -- スコープスタック

  local function emit(op, arg)
    self.code[#self.code+1]={op=op, arg=arg or 0}
    return #self.code
  end
  local function patch(idx, arg)
    self.code[idx].arg=arg
  end
  local function here() return #self.code end

  local function addConst(v)
    local k=tostring(v)
    if self.const_idx[k] then return self.const_idx[k] end
    self.consts[#self.consts+1]=v
    local idx=#self.consts
    self.const_idx[k]=idx
    return idx
  end
  local function addName(n)
    if self.name_idx[n] then return self.name_idx[n] end
    self.names[#self.names+1]=n
    local idx=#self.names
    self.name_idx[n]=idx
    return idx
  end

  local function isLocal(name)
    for i=#self.locals,1,-1 do
      if self.locals[i]==name then return true end
    end
    return false
  end
  local function pushScope()
    self.scope[#self.scope+1]=#self.locals
    emit(OP.ENTER_SCOPE)
  end
  local function popScope()
    local prev=self.scope[#self.scope]
    self.scope[#self.scope]=nil
    while #self.locals>prev do self.locals[#self.locals]=nil end
    emit(OP.LEAVE_SCOPE)
  end

  -- 前方宣言
  local parseExpr, parseBlock, parseStat

  -- ── 式パーサ ──────────────────────────────────
  local function parsePrimaryExpr()
    local t=lex:peek()
    if t.type==TK.NAME then
      lex:next()
      local ni=addName(t.value)
      if isLocal(t.value) then emit(OP.PUSH_VAR, ni)
      else emit(OP.PUSH_GLOBAL, ni) end
    elseif t.type==TK.LPAREN then
      lex:next(); parseExpr(); lex:expect(TK.RPAREN)
    else
      die("unexpected token in primary: "..t.type.." line "..t.line)
    end
  end

  local function parseSuffixedExpr()
    parsePrimaryExpr()
    while true do
      local t=lex:peek()
      if t.type==TK.DOT then
        lex:next()
        local name=lex:expect(TK.NAME)
        emit(OP.GET_FIELD, addName(name.value))
      elseif t.type==TK.LBRACKET then
        lex:next(); parseExpr(); lex:expect(TK.RBRACKET)
        emit(OP.GET_TABLE)
      elseif t.type==TK.COLON then
        lex:next()
        local name=lex:expect(TK.NAME)
        emit(OP.DUP) -- self
        emit(OP.GET_FIELD, addName(name.value))
        -- swap: method below self on stack
        -- parse call args
        local nargs=1 -- self counts
        if lex:check(TK.LPAREN) then
          lex:next()
          if not lex:check(TK.RPAREN) then
            parseExpr(); nargs=nargs+1
            while lex:match(TK.COMMA) do parseExpr(); nargs=nargs+1 end
          end
          lex:expect(TK.RPAREN)
        elseif lex:check(TK.STRING) then
          local s=lex:next()
          emit(OP.PUSH_STR, addConst(s.value)); nargs=nargs+1
        elseif lex:check(TK.LBRACE) then
          parseTableConstructor(); nargs=nargs+1
        end
        emit(OP.CALL, nargs)
      elseif t.type==TK.LPAREN then
        lex:next()
        local nargs=0
        if not lex:check(TK.RPAREN) then
          parseExpr(); nargs=1
          while lex:match(TK.COMMA) do parseExpr(); nargs=nargs+1 end
        end
        lex:expect(TK.RPAREN)
        emit(OP.CALL, nargs)
      elseif t.type==TK.STRING then
        local s=lex:next()
        emit(OP.PUSH_STR, addConst(s.value))
        emit(OP.CALL, 1)
      elseif t.type==TK.LBRACE then
        parseTableConstructor()
        emit(OP.CALL, 1)
      else break end
    end
  end

  local function parseFuncBody()
    -- create sub-compiler
    local sub=Compiler(lex)
    sub.locals={}; sub.scope={}
    lex:expect(TK.LPAREN)
    local params={}
    if not lex:check(TK.RPAREN) then
      if lex:check(TK.DOTS) then lex:next()
      else
        local p=lex:expect(TK.NAME); params[#params+1]=p.value
        while lex:match(TK.COMMA) do
          if lex:check(TK.DOTS) then lex:next();break end
          p=lex:expect(TK.NAME); params[#params+1]=p.value
        end
      end
    end
    lex:expect(TK.RPAREN)
    -- params become locals
    for _,p in ipairs(params) do
      sub.locals[#sub.locals+1]=p
    end
    sub:compileBlock()
    lex:expect(TK["end"])
    -- store sub function
    self.funcs[#self.funcs+1]={code=sub.code,consts=sub.consts,names=sub.names,funcs=sub.funcs,params=#params}
    return #self.funcs
  end

  function parseTableConstructor()
    lex:expect(TK.LBRACE)
    emit(OP.NEW_TABLE)
    local count=0
    while not lex:check(TK.RBRACE) do
      if lex:check(TK.LBRACKET) then
        lex:next(); parseExpr(); lex:expect(TK.RBRACKET)
        lex:expect(TK.ASSIGN); parseExpr()
        emit(OP.SET_TABLE)
      elseif lex:check(TK.NAME) and lex:peek(1).type==TK.ASSIGN then
        local name=lex:next(); lex:next()
        parseExpr()
        emit(OP.SET_FIELD, addName(name.value))
      else
        parseExpr(); count=count+1
      end
      if not lex:match(TK.COMMA) then lex:match(TK.SEMICOLON) end
      if lex:check(TK.RBRACE) then break end
    end
    lex:expect(TK.RBRACE)
    if count>0 then emit(OP.SETLIST, count) end
  end

  local function parseSimpleExpr()
    local t=lex:peek()
    if t.type==TK.NUMBER then
      lex:next(); emit(OP.PUSH_NUM, addConst(t.value))
    elseif t.type==TK.STRING then
      lex:next(); emit(OP.PUSH_STR, addConst(t.value))
    elseif t.type==TK.TRUE then lex:next(); emit(OP.PUSH_TRUE)
    elseif t.type==TK.FALSE then lex:next(); emit(OP.PUSH_FALSE)
    elseif t.type==TK.NIL then lex:next(); emit(OP.PUSH_NIL)
    elseif t.type==TK.DOTS then lex:next(); emit(OP.PUSH_VARARG)
    elseif t.type==TK.FUNCTION then lex:next(); local fi=parseFuncBody(); emit(OP.CLOSURE,fi)
    elseif t.type==TK.LBRACE then parseTableConstructor()
    else parseSuffixedExpr() end
  end

  local UNOP={[TK.MINUS]=OP.UNM,[TK.NOT]=OP.NOT,[TK.HASH]=OP.LEN,[TK.TILDE]=OP.BNOT}
  local BINOP_PRIO={
    [TK.OR]={1,1},[TK.AND]={2,2},
    [TK.LT]={3,3},[TK.GT]={3,3},[TK.LEQ]={3,3},[TK.GEQ]={3,3},[TK.NEQ]={3,3},[TK.EQ]={3,3},
    [TK.PIPE]={4,4},[TK.TILDE]={5,5},[TK.AMPERSAND]={6,6},
    [TK.LSHIFT]={7,7},[TK.RSHIFT]={7,7},
    [TK.CONCAT]={8,7}, -- right assoc
    [TK.PLUS]={9,9},[TK.MINUS]={9,9},
    [TK.STAR]={10,10},[TK.SLASH]={10,10},[TK.DSLASH]={10,10},[TK.PERCENT]={10,10},
    [TK.CARET]={12,11}, -- right assoc
  }
  local BINOP_EMIT={
    [TK.PLUS]=OP.ADD,[TK.MINUS]=OP.SUB,[TK.STAR]=OP.MUL,[TK.SLASH]=OP.DIV,
    [TK.PERCENT]=OP.MOD,[TK.CARET]=OP.POW,[TK.DSLASH]=OP.IDIV,
    [TK.AMPERSAND]=OP.BAND,[TK.PIPE]=OP.BOR,[TK.TILDE]=OP.BXOR,
    [TK.LSHIFT]=OP.SHL,[TK.RSHIFT]=OP.SHR,
    [TK.CONCAT]=OP.CONCAT,
    [TK.EQ]=OP.EQ,[TK.NEQ]=OP.NEQ,[TK.LT]=OP.LT,[TK.GT]=OP.GT,[TK.LEQ]=OP.LEQ,[TK.GEQ]=OP.GEQ,
  }

  parseExpr = function(limit)
    limit = limit or 0
    local t=lex:peek()
    local uop=UNOP[t.type]
    if uop then
      lex:next(); parseExpr(11); emit(uop)
    else
      parseSimpleExpr()
    end

    local prio=BINOP_PRIO[lex:peek().type]
    while prio and prio[1]>limit do
      local op=lex:next()
      if op.type==TK.AND then
        local j=emit(OP.AND_JMP,0); parseExpr(prio[2]); patch(j,here()-j)
      elseif op.type==TK.OR then
        local j=emit(OP.OR_JMP,0); parseExpr(prio[2]); patch(j,here()-j)
      else
        parseExpr(prio[2])
        emit(BINOP_EMIT[op.type] or OP.ADD)
      end
      prio=BINOP_PRIO[lex:peek().type]
    end
  end

  -- ── 文パーサ ──────────────────────────────────
  local function parseExprList()
    local n=1; parseExpr()
    while lex:match(TK.COMMA) do parseExpr(); n=n+1 end
    return n
  end

  local function parseAssignOrCall()
    -- まず左辺を解析
    local t=lex:peek()
    if t.type~=TK.NAME then die("expected name at line "..t.line) end
    lex:next()
    local ni=addName(t.value)
    local isLoc=isLocal(t.value)

    -- suffix chain (field access / index)
    local suffixes={}
    while true do
      local p=lex:peek()
      if p.type==TK.DOT then
        lex:next(); local n2=lex:expect(TK.NAME)
        suffixes[#suffixes+1]={type="field",name=n2.value}
      elseif p.type==TK.LBRACKET then
        lex:next(); parseExpr(); lex:expect(TK.RBRACKET)
        suffixes[#suffixes+1]={type="index"}
      elseif p.type==TK.COLON then
        -- method call
        lex:next(); local mn=lex:expect(TK.NAME)
        if isLoc then emit(OP.PUSH_VAR,ni) else emit(OP.PUSH_GLOBAL,ni) end
        for _,s in ipairs(suffixes) do
          if s.type=="field" then emit(OP.GET_FIELD,addName(s.name))
          elseif s.type=="index" then emit(OP.GET_TABLE) end
        end
        emit(OP.DUP)
        emit(OP.GET_FIELD,addName(mn.value))
        local nargs=1
        lex:expect(TK.LPAREN)
        if not lex:check(TK.RPAREN) then parseExpr();nargs=nargs+1;while lex:match(TK.COMMA)do parseExpr();nargs=nargs+1 end end
        lex:expect(TK.RPAREN)
        emit(OP.CALL,nargs); return
      elseif p.type==TK.LPAREN or p.type==TK.STRING or p.type==TK.LBRACE then
        -- function call
        if isLoc then emit(OP.PUSH_VAR,ni) else emit(OP.PUSH_GLOBAL,ni) end
        for _,s in ipairs(suffixes) do
          if s.type=="field" then emit(OP.GET_FIELD,addName(s.name))
          elseif s.type=="index" then emit(OP.GET_TABLE) end
        end
        local nargs=0
        if p.type==TK.LPAREN then
          lex:next()
          if not lex:check(TK.RPAREN) then parseExpr();nargs=1;while lex:match(TK.COMMA)do parseExpr();nargs=nargs+1 end end
          lex:expect(TK.RPAREN)
        elseif p.type==TK.STRING then
          local s=lex:next(); emit(OP.PUSH_STR,addConst(s.value)); nargs=1
        else parseTableConstructor(); nargs=1 end
        emit(OP.CALL,nargs); return
      else break end
    end

    -- 代入
    -- 複数代入: a,b = ...
    local lhs_extra={}
    while lex:match(TK.COMMA) do
      local n2=lex:peek()
      if n2.type==TK.NAME then
        lex:next()
        lhs_extra[#lhs_extra+1]={name=n2.value,suffixes={}}
        while true do
          local p2=lex:peek()
          if p2.type==TK.DOT then lex:next();local f=lex:expect(TK.NAME);lhs_extra[#lhs_extra].suffixes[#lhs_extra[#lhs_extra].suffixes+1]={type="field",name=f.value}
          elseif p2.type==TK.LBRACKET then lex:next();parseExpr();lex:expect(TK.RBRACKET);lhs_extra[#lhs_extra].suffixes[#lhs_extra[#lhs_extra].suffixes+1]={type="index"}
          else break end
        end
      end
    end

    lex:expect(TK.ASSIGN)
    local total=1+#lhs_extra
    local nvals=parseExprList()
    -- adjust values
    if nvals~=total then emit(OP.ADJUST,total) end

    -- 逆順に代入
    for i=#lhs_extra,1,-1 do
      local lx=lhs_extra[i]
      local li=isLocal(lx.name)
      local lni=addName(lx.name)
      if #lx.suffixes==0 then
        if li then emit(OP.SET_LOCAL,lni) else emit(OP.SET_GLOBAL,lni) end
      else
        if li then emit(OP.PUSH_VAR,lni) else emit(OP.PUSH_GLOBAL,lni) end
        for si=1,#lx.suffixes-1 do
          local s=lx.suffixes[si]
          if s.type=="field" then emit(OP.GET_FIELD,addName(s.name)) else emit(OP.GET_TABLE) end
        end
        local ls=lx.suffixes[#lx.suffixes]
        if ls.type=="field" then emit(OP.SET_FIELD,addName(ls.name)) else emit(OP.SET_TABLE) end
      end
    end
    -- first lhs
    if #suffixes==0 then
      if isLoc then emit(OP.SET_LOCAL,ni) else emit(OP.SET_GLOBAL,ni) end
    else
      if isLoc then emit(OP.PUSH_VAR,ni) else emit(OP.PUSH_GLOBAL,ni) end
      for si=1,#suffixes-1 do
        local s=suffixes[si]
        if s.type=="field" then emit(OP.GET_FIELD,addName(s.name)) else emit(OP.GET_TABLE) end
      end
      local ls=suffixes[#suffixes]
      if ls.type=="field" then emit(OP.SET_FIELD,addName(ls.name)) else emit(OP.SET_TABLE) end
    end
  end

  parseStat = function()
    local t=lex:peek()

    if t.type==TK.SEMICOLON then lex:next()

    elseif t.type==TK["if"] then
      lex:next(); parseExpr(); lex:expect(TK.THEN)
      local j1=emit(OP.JMP_FALSE,0)
      pushScope(); parseBlock(); popScope()
      local exits={}
      while lex:check(TK.ELSEIF) do
        lex:next()
        exits[#exits+1]=emit(OP.JMP,0)
        patch(j1,here()-j1)
        parseExpr(); lex:expect(TK.THEN)
        j1=emit(OP.JMP_FALSE,0)
        pushScope(); parseBlock(); popScope()
      end
      if lex:match(TK.ELSE) then
        exits[#exits+1]=emit(OP.JMP,0)
        patch(j1,here()-j1)
        pushScope(); parseBlock(); popScope()
      else
        exits[#exits+1]=emit(OP.JMP,0)
        patch(j1,here()-j1)
      end
      for _,e in ipairs(exits) do patch(e,here()-e) end
      lex:expect(TK["end"])

    elseif t.type==TK.WHILE then
      lex:next()
      local loop_start=here()
      parseExpr()
      local jf=emit(OP.JMP_FALSE,0)
      lex:expect(TK.DO)
      pushScope(); parseBlock(); popScope()
      lex:expect(TK["end"])
      emit(OP.JMP, loop_start-here()-1)
      patch(jf,here()-jf)

    elseif t.type==TK.DO then
      lex:next(); pushScope(); parseBlock(); popScope(); lex:expect(TK["end"])

    elseif t.type==TK.FOR then
      lex:next()
      local var=lex:expect(TK.NAME)
      if lex:check(TK.ASSIGN) then
        -- numeric for
        lex:next(); parseExpr(); lex:expect(TK.COMMA); parseExpr()
        local has_step=false
        if lex:match(TK.COMMA) then parseExpr(); has_step=true end
        if not has_step then emit(OP.PUSH_NUM,addConst(1)) end
        lex:expect(TK.DO)
        local fp=emit(OP.FORPREP,0)
        pushScope()
        self.locals[#self.locals+1]=var.value
        local loop_body=here()
        parseBlock()
        popScope()
        lex:expect(TK["end"])
        local fl=emit(OP.FORLOOP, loop_body-here()-1)
        patch(fp, here()-fp)
      else
        -- generic for
        lex:expect(TK.IN)
        local nvars=1
        local varnames={var.value}
        while lex:match(TK.COMMA) do
          local v=lex:expect(TK.NAME); varnames[#varnames+1]=v.value; nvars=nvars+1
        end
        parseExprList()
        lex:expect(TK.DO)
        local gfp=emit(OP.GFORPREP,0)
        pushScope()
        for _,vn in ipairs(varnames) do self.locals[#self.locals+1]=vn end
        local loop_body=here()
        parseBlock()
        popScope()
        lex:expect(TK["end"])
        emit(OP.GFORLOOP, loop_body-here()-1)
        patch(gfp, here()-gfp)
      end

    elseif t.type==TK.REPEAT then
      lex:next()
      local loop_start=here()
      pushScope(); parseBlock(); popScope()
      lex:expect(TK.UNTIL)
      parseExpr()
      emit(OP.JMP_FALSE, loop_start-here()-1)

    elseif t.type==TK["function"] then
      lex:next()
      local name=lex:expect(TK.NAME)
      -- a.b.c 形式
      local fields={}
      while lex:match(TK.DOT) do fields[#fields+1]=lex:expect(TK.NAME).value end
      local is_method=false
      if lex:match(TK.COLON) then
        fields[#fields+1]=lex:expect(TK.NAME).value; is_method=true
      end
      local fi=parseFuncBody()
      emit(OP.CLOSURE,fi)
      if #fields==0 then
        local ni2=addName(name.value)
        if isLocal(name.value) then emit(OP.SET_LOCAL,ni2) else emit(OP.SET_GLOBAL,ni2) end
      else
        local ni2=addName(name.value)
        if isLocal(name.value) then emit(OP.PUSH_VAR,ni2) else emit(OP.PUSH_GLOBAL,ni2) end
        for i=1,#fields-1 do emit(OP.GET_FIELD,addName(fields[i])) end
        emit(OP.SET_FIELD,addName(fields[#fields]))
      end

    elseif t.type==TK.LOCAL then
      lex:next()
      if lex:check(TK["function"]) then
        lex:next()
        local name=lex:expect(TK.NAME)
        self.locals[#self.locals+1]=name.value
        emit(OP.PUSH_NIL)
        emit(OP.DEF_LOCAL,addName(name.value))
        local fi=parseFuncBody()
        emit(OP.CLOSURE,fi)
        emit(OP.SET_LOCAL,addName(name.value))
      else
        local names2={}
        local n2=lex:expect(TK.NAME); names2[#names2+1]=n2.value
        while lex:match(TK.COMMA) do
          local n3=lex:expect(TK.NAME); names2[#names2+1]=n3.value
        end
        local nvals=0
        if lex:match(TK.ASSIGN) then nvals=parseExprList() end
        if nvals<#names2 then
          for _=nvals+1,#names2 do emit(OP.PUSH_NIL) end
        elseif nvals>#names2 then
          emit(OP.ADJUST,#names2)
        end
        for i=#names2,1,-1 do
          self.locals[#self.locals+1]=names2[i]
          emit(OP.DEF_LOCAL,addName(names2[i]))
        end
      end

    elseif t.type==TK.RETURN then
      lex:next()
      local nvals=0
      if not lex:check(TK["end"]) and not lex:check(TK.ELSE) and
         not lex:check(TK.ELSEIF) and not lex:check(TK.UNTIL) and
         not lex:check(TK.EOF) and not lex:check(TK.SEMICOLON) then
        nvals=parseExprList()
      end
      lex:match(TK.SEMICOLON)
      emit(OP.RETURN,nvals)

    elseif t.type==TK.BREAK then
      lex:next()
      emit(OP.JMP,0) -- will be patched by loop handler (simple impl: just jump 0)

    elseif t.type==TK.GOTO then
      lex:next(); lex:expect(TK.NAME) -- ignore goto for now

    elseif t.type==TK.DCOLON then
      lex:next(); lex:expect(TK.NAME); lex:expect(TK.DCOLON) -- ignore labels

    elseif t.type==TK.NAME then
      parseAssignOrCall()
    else
      return false
    end
    return true
  end

  parseBlock = function()
    while true do
      local t=lex:peek()
      if t.type==TK.EOF or t.type==TK["end"] or t.type==TK.ELSE or
         t.type==TK.ELSEIF or t.type==TK.UNTIL then break end
      if not parseStat() then break end
    end
  end

  function self:compileBlock() parseBlock() end

  function self:compile()
    parseBlock()
    emit(OP.RETURN,0)
    return {
      code=self.code, consts=self.consts, names=self.names,
      funcs=self.funcs, params=0
    }
  end

  return self
end

-- ═══════════════════════════════════════════════
--  コンパイル実行
-- ═══════════════════════════════════════════════
local lex = Lexer(source)
local compiler = Compiler(lex)
local ok, result = pcall(function() return compiler:compile() end)
if not ok then
  io.stderr:write("VM_OBF_WARN: compile failed: "..tostring(result).."\nFalling back to encrypted source\n")
  -- フォールバック
  local sa2,sb2,sc2=seed,(seed*22695477+1)%4294967296,(seed*1103515245+12345)%4294967296
  local function prng2()
    sa2=(sa2*1664525+1013904223)%4294967296
    sb2=(sb2*22695477+1)%4294967296
    sc2=(sc2*1103515245+12345)%4294967296
    local v=sa2; v=v-sb2; if v<0 then v=v+4294967296 end
    return (v+sc2)%4294967296%256
  end
  local CHSZ=math.max(32,math.floor(#source/16))
  local chs,cvars={},{}
  local pos3=1
  while pos3<=#source do
    local cd=source:sub(pos3,pos3+CHSZ-1); pos3=pos3+CHSZ
    local k3=prng2()%40+5
    local enc={}
    for i=1,#cd do enc[i]=ne((cd:byte(i)+k3+(i%7)*3)%256) end
    local vt2,vr2,vi2=V(),V(),V()
    chs[#chs+1]=("(function()local %s={%s};local %s={};for %s=1,#%s do %s[%s]=string.char((%s[%s]-%d-(%s-1)%%7*3+512)%%256)end;return table.concat(%s)end)()"):format(
      vt2,table.concat(enc,","),vr2,vi2,vt2,vr2,vi2,vt2,vi2,k3,vi2,vr2)
    cvars[#cvars+1]=V()
  end
  local ord={}; for i=1,#chs do ord[i]=i end
  for i=#ord,2,-1 do local j=(rng()%i)+1; ord[i],ord[j]=ord[j],ord[i] end
  local lsk=(rng()%40)+5
  local lse={}
  for i=1,#"loadstring" do lse[i]=ne(("loadstring"):byte(i)+lsk) end
  local vLt,vLr2,vLi,vLn,vLf=V(),V(),V(),V(),V()
  local ls2=("local %s={%s};local %s={};for %s=1,#%s do %s[%s]=string.char(%s[%s]-%d)end;local %s=table.concat(%s);local %s=_G[%s] or load"):format(
    vLt,table.concat(lse,","),vLr2,vLi,vLt,vLr2,vLi,vLt,vLi,lsk,vLn,vLr2,vLf,vLn)
  local sorted_vars={}
  for i=1,#ord do sorted_vars[i]=cvars[ord[i]] end
  local vSrc2=V()
  local fb_lines={"(function()"}
  fb_lines[#fb_lines+1]=ls2
  for i=1,#chs do fb_lines[#fb_lines+1]=("local %s=%s"):format(cvars[i],chs[i]) end
  fb_lines[#fb_lines+1]=("local %s=%s"):format(vSrc2,table.concat(sorted_vars,".."))
  fb_lines[#fb_lines+1]=("%s(%s)()"):format(vLf,vSrc2)
  fb_lines[#fb_lines+1]="end)()"
  local fw3=io.open(output_file,"w")
  if not fw3 then die("cannot write: "..output_file) end
  fw3:write(table.concat(fb_lines,"\n")); fw3:close()
  io.write("OK:"..output_file)
  os.exit(0)
end

local proto = result

-- ═══════════════════════════════════════════════
--  opcode シャッフル
-- ═══════════════════════════════════════════════
math.randomseed(seed)
local MAX_OP=55
local pool={}; for i=1,MAX_OP do pool[i]=i end
for i=MAX_OP,2,-1 do local j=math.random(1,i); pool[i],pool[j]=pool[j],pool[i] end
local op_to_code={}  -- original → shuffled
local code_to_op={}  -- shuffled → original
for i=1,MAX_OP do op_to_code[i]=pool[i]; code_to_op[pool[i]]=i end

local function remap_proto_ops(p)
  for _,ins in ipairs(p.code) do
    ins.op = op_to_code[ins.op] or ins.op
  end
  for _,sub in ipairs(p.funcs) do remap_proto_ops(sub) end
end
remap_proto_ops(proto)

-- ═══════════════════════════════════════════════
--  シリアライズ (難読化テーブルとして出力)
-- ═══════════════════════════════════════════════
local function serial(p)
  -- 定数
  local kp={}
  for _,c in ipairs(p.consts) do
    if type(c)=="number" then
      if c==math.floor(c) and math.abs(c)<1e12 then kp[#kp+1]=ne(math.floor(c))
      else kp[#kp+1]=tostring(c) end
    elseif type(c)=="string" then kp[#kp+1]=hide_str(c)
    else kp[#kp+1]=tostring(c) end
  end
  -- 名前
  local np={}
  for _,n in ipairs(p.names) do np[#np+1]=hide_str(n) end
  -- 命令
  local cp={}
  for _,ins in ipairs(p.code) do
    cp[#cp+1]=("{%s,%s}"):format(ne(ins.op),ne(ins.arg))
  end
  -- サブ関数
  local fp={}
  for _,sub in ipairs(p.funcs) do fp[#fp+1]=serial(sub) end
  return ("{k={%s},n={%s},c={%s},f={%s},p=%s}"):format(
    table.concat(kp,","),
    table.concat(np,","),
    table.concat(cp,","),
    table.concat(fp,","),
    ne(p.params or 0))
end

local proto_str=serial(proto)

-- unmap table (shuffled→original)
local unmap_parts={}
for k,v in pairs(code_to_op) do
  unmap_parts[#unmap_parts+1]=("[%s]=%s"):format(ne(k),ne(v))
end
local unmap_str="{"..table.concat(unmap_parts,",").."}"

-- ═══════════════════════════════════════════════
--  VMランタイム生成
-- ═══════════════════════════════════════════════
local lines={}
local function L(s) lines[#lines+1]=s end

-- 変数名
local vUM=V()   -- unmap
local vPR=V()   -- proto
local vRUN=V()  -- run function
local vP=V()    -- proto arg
local vEnv=V()  -- env
local vArgs=V() -- args
local vSTK=V()  -- stack
local vSP=V()   -- stack pointer
local vPC=V()   -- program counter
local vINS=V()  -- instruction
local vOP=V()   -- opcode
local vARG=V()  -- arg
local vLOCS=V() -- locals table
local vSCPS=V() -- scope stack

-- スタック操作マクロ的変数名
local vPUSH=V(); local vPOP=V(); local vTOP=V()

L("(function()")
L(("local %s=%s"):format(vUM,unmap_str))
L(("local %s=%s"):format(vPR,proto_str))

-- ランタイム関数
L(("local %s"):format(vRUN))
L(("%s=function(%s,%s,%s)"):format(vRUN,vP,vEnv,vArgs))
L(("  local %s=%s or _G"):format(vEnv,vEnv))
L(("  local %s={}"):format(vSTK))   -- スタック
L(("  local %s=0"):format(vSP))     -- スタックポインタ
L(("  local %s=1"):format(vPC))     -- プログラムカウンタ
L(("  local %s={}"):format(vLOCS))  -- ローカル変数 {name→value}
L(("  local %s={}"):format(vSCPS))  -- スコープ (各スコープ: ローカル名リスト)

-- パラメータをローカルに設定
L(("  if %s then"):format(vArgs))
L(("    for _pi=1,%s.p do %s[%s.n[_pi]]=%s[_pi] end"):format(vP,vLOCS,vP,vArgs))
L("  end")

-- push/pop/top ヘルパー
L(("  local function %s(v) %s=%s+1;%s[%s]=v end"):format(vPUSH,vSP,vSP,vSTK,vSP))
L(("  local function %s() local v=%s[%s];%s[%s]=nil;%s=%s-1;return v end"):format(vPOP,vSTK,vSP,vSTK,vSP,vSP,vSP))
L(("  local function %s() return %s[%s] end"):format(vTOP,vSTK,vSP))

-- メインループ
L("  while true do")
L(("    local %s=%s.c[%s]"):format(vINS,vP,vPC))
L(("    if not %s then break end"):format(vINS))
L(("    local %s=%s[%s[1]]"):format(vOP,vUM,vINS))
L(("    local %s=%s[2]"):format(vARG,vINS))
L(("    %s=%s+1"):format(vPC,vPC))

-- 各opcode (code_to_op でunmapしてから比較)
local O=code_to_op  -- shuffled→original のマップ
-- original OP番号を難読化した式で返す
local function oc(name) return ne(OP[name]) end

L(("    if %s==%s then %s(nil)"):format(vOP,oc("PUSH_NIL"),vPUSH))
L(("    elseif %s==%s then %s(true)"):format(vOP,oc("PUSH_TRUE"),vPUSH))
L(("    elseif %s==%s then %s(false)"):format(vOP,oc("PUSH_FALSE"),vPUSH))
L(("    elseif %s==%s then %s(%s.k[%s])"):format(vOP,oc("PUSH_NUM"),vPUSH,vP,vARG))
L(("    elseif %s==%s then %s(%s.k[%s])"):format(vOP,oc("PUSH_STR"),vPUSH,vP,vARG))
-- PUSH_VAR: ローカル変数を積む
L(("    elseif %s==%s then"):format(vOP,oc("PUSH_VAR")))
L(("      local _n=%s.n[%s];%s(%s[_n])"):format(vP,vARG,vPUSH,vLOCS))
-- PUSH_GLOBAL
L(("    elseif %s==%s then"):format(vOP,oc("PUSH_GLOBAL")))
L(("      local _n=%s.n[%s];%s(%s[_n])"):format(vP,vARG,vPUSH,vEnv))
-- POP
L(("    elseif %s==%s then %s()"):format(vOP,oc("POP"),vPOP))
-- SET_LOCAL
L(("    elseif %s==%s then"):format(vOP,oc("SET_LOCAL")))
L(("      local _n=%s.n[%s];%s[_n]=%s()"):format(vP,vARG,vLOCS,vPOP))
-- SET_GLOBAL
L(("    elseif %s==%s then"):format(vOP,oc("SET_GLOBAL")))
L(("      local _n=%s.n[%s];%s[_n]=%s()"):format(vP,vARG,vEnv,vPOP))
-- DEF_LOCAL: スコープに登録してローカルにセット
L(("    elseif %s==%s then"):format(vOP,oc("DEF_LOCAL")))
L(("      local _n=%s.n[%s];local _v=%s()"):format(vP,vARG,vPOP))
L(("      if #%s>0 then local _sc=%s[#%s];_sc[#_sc+1]=_n end"):format(vSCPS,vSCPS,vSCPS))
L(("      %s[_n]=_v"):format(vLOCS))
-- NEW_TABLE
L(("    elseif %s==%s then %s({})"):format(vOP,oc("NEW_TABLE"),vPUSH))
-- GET_TABLE: key=pop, tbl=pop → push(tbl[key])
L(("    elseif %s==%s then local _k=%s();local _t=%s();%s(_t[_k])"):format(vOP,oc("GET_TABLE"),vPOP,vPOP,vPUSH))
-- SET_TABLE: val=pop, key=pop, tbl=top
L(("    elseif %s==%s then local _v=%s();local _k=%s();local _t=%s();_t[_k]=_v"):format(vOP,oc("SET_TABLE"),vPOP,vPOP,vPOP))
-- GET_FIELD
L(("    elseif %s==%s then local _t=%s();local _fn=%s.n[%s];%s(_t[_fn])"):format(vOP,oc("GET_FIELD"),vPOP,vP,vARG,vPUSH))
-- SET_FIELD: val=pop, tbl=pop
L(("    elseif %s==%s then local _v=%s();local _t=%s();local _fn=%s.n[%s];_t[_fn]=_v"):format(vOP,oc("SET_FIELD"),vPOP,vPOP,vP,vARG))
-- 算術
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a+_b)"):format(vOP,oc("ADD"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a-_b)"):format(vOP,oc("SUB"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a*_b)"):format(vOP,oc("MUL"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a/_b)"):format(vOP,oc("DIV"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a%%_b)"):format(vOP,oc("MOD"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a^_b)"):format(vOP,oc("POW"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(math.floor(_a/_b))"):format(vOP,oc("IDIV"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then %s(-%s())"):format(vOP,oc("UNM"),vPUSH,vPOP))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a.._b)"):format(vOP,oc("CONCAT"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then %s(#%s())"):format(vOP,oc("LEN"),vPUSH,vPOP))
-- 比較
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a==_b)"):format(vOP,oc("EQ"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a~=_b)"):format(vOP,oc("NEQ"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a<_b)"):format(vOP,oc("LT"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a>_b)"):format(vOP,oc("GT"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a<=_b)"):format(vOP,oc("LEQ"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then local _b=%s();local _a=%s();%s(_a>=_b)"):format(vOP,oc("GEQ"),vPOP,vPOP,vPUSH))
L(("    elseif %s==%s then %s(not %s())"):format(vOP,oc("NOT"),vPUSH,vPOP))
-- AND_JMP: トップが falsy なら jump、そうでなければ pop して続行
L(("    elseif %s==%s then"):format(vOP,oc("AND_JMP")))
L(("      if not %s() then %s=%s+%s-1 else %s() end"):format(vTOP,vPC,vPC,vARG,vPOP))
-- OR_JMP
L(("    elseif %s==%s then"):format(vOP,oc("OR_JMP")))
L(("      if %s() then %s=%s+%s-1 else %s() end"):format(vTOP,vPC,vPC,vARG,vPOP))
-- JMP
L(("    elseif %s==%s then %s=%s+%s-1"):format(vOP,oc("JMP"),vPC,vPC,vARG))
-- JMP_FALSE
L(("    elseif %s==%s then local _v=%s();if not _v then %s=%s+%s-1 end"):format(vOP,oc("JMP_FALSE"),vPOP,vPC,vPC,vARG))
-- JMP_TRUE
L(("    elseif %s==%s then local _v=%s();if _v then %s=%s+%s-1 end"):format(vOP,oc("JMP_TRUE"),vPOP,vPC,vPC,vARG))
-- CALL: arg=nargs, stack: [fn, a1, a2, ...aN] (先頭がfn)
L(("    elseif %s==%s then"):format(vOP,oc("CALL")))
L("      local _args={}")
L(("      for _i=%s,1,-1 do _args[_i]=%s() end"):format(vARG,vPOP))
L(("      local _fn=%s()"):format(vPOP))
L("      local _rets={_fn(table.unpack and table.unpack(_args) or unpack(_args))}")
L(("      for _,_r in ipairs(_rets) do %s(_r) end"):format(vPUSH))
-- RETURN
L(("    elseif %s==%s then"):format(vOP,oc("RETURN")))
L("      if "..vARG.."==0 then return end")
L("      local _rv={}")
L(("      for _i=%s,1,-1 do _rv[_i]=%s() end"):format(vARG,vPOP))
L("      return table.unpack and table.unpack(_rv) or unpack(_rv)")
-- CLOSURE
L(("    elseif %s==%s then"):format(vOP,oc("CLOSURE")))
L(("      local _sf=%s.f[%s]"):format(vP,vARG))
L(("      local _ce=%s; local _cl=%s"):format(vEnv,vLOCS))
L(("      %s(function(...)"):format(vPUSH))
L(("        local _fa={...}"):format())
L(("        return %s(_sf,_ce,_fa)"):format(vRUN))
L("      end)")
-- DUP
L(("    elseif %s==%s then %s(%s())"):format(vOP,oc("DUP"),vPUSH,vTOP))
-- SETLIST: 配列部分をテーブルに格納
L(("    elseif %s==%s then"):format(vOP,oc("SETLIST")))
L("      local _vals={}")
L(("      for _i=%s,1,-1 do _vals[_i]=%s() end"):format(vARG,vPOP))
L(("      local _tbl=%s()"):format(vTOP))
L(("      for _i,_v in ipairs(_vals) do _tbl[_i]=_v end"):format())
-- FORPREP: limit=pop, step=pop, init=pop; push all back; check exit
L(("    elseif %s==%s then"):format(vOP,oc("FORPREP")))
L("      local _step=_pop_(); local _lim=_pop_(); local _init=_pop_()")
L(("      %s(_init);%s(_lim);%s(_step)"):format(vPUSH,vPUSH,vPUSH))
-- define push/pop aliases for FORPREP
-- (already using vPOP/vPUSH)
-- FORLOOP
L(("    elseif %s==%s then"):format(vOP,oc("FORLOOP")))
L(("      local _step=%s[%s];local _lim=%s[%s-1];local _cur=%s[%s-2]"):format(vSTK,vSP,vSTK,vSP,vSTK,vSP))
L("      _cur=_cur+_step")
L(("      %s[%s-2]=_cur"):format(vSTK,vSP))
L("      if (_step>0 and _cur<=_lim) or (_step<=0 and _cur>=_lim) then")
L(("        %s=%s+%s-1"):format(vPC,vPC,vARG))
L("      else")
L(("        %s();%s();%s()"):format(vPOP,vPOP,vPOP)) -- clean up for vars
L("      end")
-- ENTER_SCOPE / LEAVE_SCOPE
L(("    elseif %s==%s then %s[#%s+1]={}"):format(vOP,oc("ENTER_SCOPE"),vSCPS,vSCPS))
L(("    elseif %s==%s then"):format(vOP,oc("LEAVE_SCOPE")))
L(("      if #%s>0 then local _sc=table.remove(%s);for _,_n in ipairs(_sc) do %s[_n]=nil end end"):format(vSCPS,vSCPS,vLOCS))
-- ADJUST: スタックをN個に調整
L(("    elseif %s==%s then"):format(vOP,oc("ADJUST")))
L(("      while %s<%s do %s(nil) end"):format(vSP,vARG,vPUSH))
L(("      while %s>%s do %s() end"):format(vSP,vARG,vPOP))
-- PUSH_VARARG
L(("    elseif %s==%s then if %s then for _,_v in ipairs(%s) do %s(_v) end end"):format(vOP,oc("PUSH_VARARG"),vArgs,vArgs,vPUSH))
-- GFORPREP/GFORLOOP (簡易)
L(("    elseif %s==%s then -- gforprep nop"):format(vOP,oc("GFORPREP")))
L(("    elseif %s==%s then"):format(vOP,oc("GFORLOOP")))
L(("      local _iter=%s[%s-2];local _st=%s[%s-1];local _ctl=%s[%s]"):format(vSTK,vSP,vSTK,vSP,vSTK,vSP))
L("      local _res={_iter(_st,_ctl)}")
L("      if _res[1]==nil then")
L(("        %s();%s();%s()"):format(vPOP,vPOP,vPOP))
L("      else")
L(("        %s[%s]=_res[1]"):format(vSTK,vSP))
L(("        %s=%s+%s-1"):format(vPC,vPC,vARG))
L("      end")

L("    end") -- end if/elseif
L("  end")   -- end while
L("end")     -- end function

-- エントリポイント
local vEntry=V()
L(("local %s=function()%s(%s,_G,{})end"):format(vEntry,vRUN,vPR))
L(("%s()"):format(vEntry))
L("end)()")

-- FORPREP/FORLOOP の _pop_ 未定義修正: インラインに書き直す
local code_str = table.concat(lines,"\n")
-- _pop_ → vPOP に置換
code_str = code_str:gsub("_pop_%(%)","("..vPOP..")()")

local fw=io.open(output_file,"w")
if not fw then die("cannot write: "..output_file) end
fw:write(code_str); fw:close()
io.write("OK:"..output_file)
