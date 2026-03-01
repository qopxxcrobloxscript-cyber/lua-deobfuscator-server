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
  if n==0 then return "0" end
  local r=rng()%3
  if r==0 then local a=(rng()%40)+2;local b=math.floor(n/a);local c=n-a*b;return("(%d*%d+%d)"):format(a,b,c)
  elseif r==1 then local o=(rng()%80)+5;return("(%d-%d)"):format(n+o,o)
  else local f=(rng()%6)+2;local q=math.floor(n/f);local c=n-f*q;return("(%d*%d+%d)"):format(f,q,c) end
end
local function hide_str(s)
  if not s or #s==0 then return '""' end
  -- ★ FIX: マルチバイト文字(日本語等)対応
  -- string.byte は生バイト列をそのまま返すので、エンコード/デコードはバイト単位で行う
  -- ただし string.char(0) (ヌル文字) が生成されると Roblox が
  -- "Attribute name is missing" を出すため、結果が 1～255 に収まるよう +1 オフセットを加える
  local key=(rng()%50)+3
  local enc={}
  for i=1,#s do
    -- (byte + key + offset) % 255 + 1  → 値域 1..255、ヌル文字なし
    enc[i]=ne((s:byte(i)+key+(i%7)*3)%255+1)
  end
  local vt,vr,vi=V(),V(),V()
  -- デコード: enc[i] = (orig + key + (i%7)*3) % 255 + 1
  -- orig = (enc[i] - 1 - key - (i%7)*3 + 255*N) % 255
  -- +510 (=255*2) で確実に正の値にする
  return("(function()local %s={%s};local %s={};for %s=1,#%s do %s[%s]=string.char((%s[%s]-1-%d-%s%%7*3+510)%%255)end;return table.concat(%s)end)()"):format(
    vt,table.concat(enc,","),vr,vi,vt,vr,vi,vt,vi,key,vi,vr)
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
        elseif p2==".." then adv(2); self.tokens[#self.tokens+1]={type=TK.CONCAT,line=line}
        elseif p2=="==" then adv(2); self.tokens[#self.tokens+1]={type=TK.EQ,line=line}
        elseif p2=="~=" then adv(2); self.tokens[#self.tokens+1]={type=TK.NEQ,line=line}
        elseif p2=="<=" then adv(2); self.tokens[#self.tokens+1]={type=TK.LEQ,line=line}
        elseif p2==">=" then adv(2); self.tokens[#self.tokens+1]={type=TK.GEQ,line=line}
        elseif p2=="<<" then adv(2); self.tokens[#self.tokens+1]={type=TK.LSHIFT,line=line}
        elseif p2==">>" then adv(2); self.tokens[#self.tokens+1]={type=TK.RSHIFT,line=line}
        elseif p2=="//" then adv(2); self.tokens[#self.tokens+1]={type=TK.DSLASH,line=line}
        elseif p2=="::" then adv(2); self.tokens[#self.tokens+1]={type=TK.DCOLON,line=line}
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
}

local function Compiler(lex)
  local self={}
  self.code={}; self.consts={}; self.const_idx={}
  self.names={}; self.name_idx={}
  self.funcs={}; self.locals={}; self.scope={}

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
  local function isLocal(n) for i=#self.locals,1,-1 do if self.locals[i]==n then return true end end end
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
      if not lex:check(TK.RPAREN) then
        parseExpr(); n=1
        while lex:match(TK.COMMA) do parseExpr(); n=n+1 end
      end
      lex:expect(TK.RPAREN); return n
    elseif t.type==TK.STRING then
      lex:next(); emit(OP.PUSH_STR, addConst(t.value)); return 1
    elseif t.type==TK.LBRACE then
      parseTableConstructor(); return 1
    else
      die("expected function args at line "..tostring(t.line))
    end
  end

  local function parseSuffixedExpr()
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
        local nargs=parseCallArgs()
        emit(OP.CALL, nargs+1)
        kind="call"; name=nil
      elseif t.type==TK.LPAREN or t.type==TK.STRING or t.type==TK.LBRACE then
        local nargs=parseCallArgs()
        emit(OP.CALL, nargs)
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
        emit(OP.SET_TABLE)
      elseif t.type==TK.NAME and lex:peek(1).type==TK.ASSIGN then
        local n=lex:next(); lex:next()
        parseExpr()
        emit(OP.SET_FIELD, addName(n.value))
      else
        parseExpr(); count=count+1
        emit(OP.SETLIST, count)
      end
      if not lex:match(TK.COMMA) then lex:match(TK.SEMI) end
      if lex:check(TK.RBRACE) then break end
    end
    lex:expect(TK.RBRACE)
  end

  function parseFuncBody()
    local sub=Compiler(lex)
    lex:expect(TK.LPAREN)
    local params={}
    if not lex:check(TK.RPAREN) then
      if lex:check(TK.DOTS) then lex:next()
      else
        local p=lex:expect(TK.NAME); params[#params+1]=p.value
        while lex:match(TK.COMMA) do
          if lex:check(TK.DOTS) then lex:next(); break end
          p=lex:expect(TK.NAME); params[#params+1]=p.value
        end
      end
    end
    lex:expect(TK.RPAREN)
    for _,p in ipairs(params) do sub.locals[#sub.locals+1]=p end
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
    if t.type==TK.NUMBER then lex:next(); emit(OP.PUSH_NUM, addConst(t.value))
    elseif t.type==TK.STRING then lex:next(); emit(OP.PUSH_STR, addConst(t.value))
    elseif t.type==TK.TRUE then lex:next(); emit(OP.PUSH_TRUE)
    elseif t.type==TK.FALSE then lex:next(); emit(OP.PUSH_FALSE)
    elseif t.type==TK.NIL then lex:next(); emit(OP.PUSH_NIL)
    elseif t.type==TK.DOTS then lex:next(); emit(OP.PUSH_VARARG)
    elseif t.type==TK.FUNCTION then lex:next(); local fi=parseFuncBody(); emit(OP.CLOSURE,fi)
    elseif t.type==TK.LBRACE then parseTableConstructor()
    else parseSuffixedExpr() end
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
    if uop then lex:next(); parseExpr(11); emit(uop)
    else parseSimpleExpr() end
    local prio=BINPRIO[lex:peek().type]
    while prio and prio[1]>limit do
      local op=lex:next()
      if op.type==TK.AND then
        local j=emit(OP.AND_JMP,0); parseExpr(prio[2]); patch(j,here()-j)
      elseif op.type==TK.OR then
        local j=emit(OP.OR_JMP,0); parseExpr(prio[2]); patch(j,here()-j)
      else
        parseExpr(prio[2]); emit(BINOP_EMIT[op.type] or OP.ADD)
      end
      prio=BINPRIO[lex:peek().type]
    end
  end

  local function parseExprList()
    local n=1; parseExpr()
    while lex:match(TK.COMMA) do parseExpr(); n=n+1 end
    return n
  end

  local function parseAssignOrCall()
    local lhs={}
    local function parseLhsOne()
      local t=lex:peek()
      if t.type~=TK.NAME then die("expected name at line "..tostring(t.line)) end
      lex:next()
      local base={name=t.value, suffixes={}}
      while true do
        local p=lex:peek()
        if p.type==TK.DOT then
          lex:next(); local f=lex:expect(TK.NAME)
          base.suffixes[#base.suffixes+1]={type="field",val=f.value}
        elseif p.type==TK.LBRACKET then
          lex:next(); parseExpr(); lex:expect(TK.RBRACKET)
          base.suffixes[#base.suffixes+1]={type="index_expr"}
        elseif p.type==TK.COLON or p.type==TK.LPAREN or p.type==TK.STRING or p.type==TK.LBRACE then
          if isLocal(base.name) then emit(OP.PUSH_VAR,addName(base.name))
          else emit(OP.PUSH_GLOBAL,addName(base.name)) end
          for _,s in ipairs(base.suffixes) do
            if s.type=="field" then emit(OP.GET_FIELD,addName(s.val))
            elseif s.type=="index_expr" then emit(OP.GET_TABLE) end
          end
          while true do
            local q=lex:peek()
            if q.type==TK.COLON then
              lex:next(); local mn=lex:expect(TK.NAME)
              emit(OP.DUP); emit(OP.GET_FIELD,addName(mn.value)); emit(OP.SWAP)
              local na=parseCallArgs(); emit(OP.CALL,na+1)
            elseif q.type==TK.LPAREN or q.type==TK.STRING or q.type==TK.LBRACE then
              local na=parseCallArgs(); emit(OP.CALL,na)
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
    while lex:check(TK.COMMA) do
      lex:next()
      local extra=parseLhsOne()
      if extra==nil then die("unexpected call in lhs") end
      lhs[#lhs+1]=extra
    end
    lex:expect(TK.ASSIGN)
    local nvals=parseExprList()
    if nvals~=#lhs then emit(OP.ADJUST,#lhs) end
    for i=#lhs,1,-1 do
      local b=lhs[i]
      if #b.suffixes==0 then
        if isLocal(b.name) then emit(OP.SET_LOCAL,addName(b.name))
        else emit(OP.SET_GLOBAL,addName(b.name)) end
      else
        if isLocal(b.name) then emit(OP.PUSH_VAR,addName(b.name))
        else emit(OP.PUSH_GLOBAL,addName(b.name)) end
        for si=1,#b.suffixes-1 do
          local s=b.suffixes[si]
          if s.type=="field" then emit(OP.GET_FIELD,addName(s.val))
          else emit(OP.GET_TABLE) end
        end
        local last=b.suffixes[#b.suffixes]
        if last.type=="field" then emit(OP.SET_FIELD,addName(last.val))
        else emit(OP.SET_TABLE) end
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
      pushScope(); parseBlock(); popScope()
      lex:expect(TK.END)
      emit(OP.JMP, ls-here()-1)
      patch(jf,here()-jf)
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
        pushScope(); self.locals[#self.locals+1]=var.value
        local lb=here(); parseBlock(); popScope(); lex:expect(TK.END)
        emit(OP.FORLOOP, lb-here()-1)
        patch(fp,here()-fp)
      else
        local names={var.value}
        while lex:match(TK.COMMA) do names[#names+1]=lex:expect(TK.NAME).value end
        lex:expect(TK.IN); parseExprList()
        lex:expect(TK.DO)
        local gfp=emit(OP.GFORPREP,0)
        pushScope()
        for _,n in ipairs(names) do self.locals[#self.locals+1]=n end
        local lb=here(); parseBlock(); popScope(); lex:expect(TK.END)
        emit(OP.GFORLOOP, lb-here()-1)
        patch(gfp,here()-gfp)
      end
    elseif t.type==TK.REPEAT then
      lex:next()
      local ls=here()
      pushScope(); parseBlock()
      lex:expect(TK.UNTIL); parseExpr(); popScope()
      emit(OP.JMP_FALSE, ls-here()-1)
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
        if lex:match(TK.ASSIGN) then nv=parseExprList() end
        if nv~=#names then emit(OP.ADJUST,#names) end
        for i=#names,1,-1 do
          self.locals[#self.locals+1]=names[i]
          emit(OP.SET_LOCAL,addName(names[i]))
        end
      end
    elseif t.type==TK.RETURN then
      lex:next()
      local nv=0
      if not (lex:check(TK.END) or lex:check(TK.ELSE) or lex:check(TK.ELSEIF)
           or lex:check(TK.UNTIL) or lex:check(TK.EOF)) then
        nv=parseExprList()
      end
      emit(OP.RETURN,nv); lex:match(TK.SEMI)
    elseif t.type==TK.BREAK then
      lex:next(); emit(OP.JMP,0)
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
    -- ★ FIX: %255+1 でヌル文字(0)を回避
    for i=1,#cd do enc[i]=ne((cd:byte(i)+k3+(i%7)*3)%255+1) end
    local vt,vr,vi=V(),V(),V()
    -- デコード: -1 して +510 で正値保証、%255 で元に戻す
    chs[#chs+1]=("(function()local %s={%s};local %s={};for %s=1,#%s do %s[%s]=string.char((%s[%s]-1-%d-%s%%7*3+510)%%255)end;return table.concat(%s)end)()"):format(
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

math.randomseed(seed)
local MAX_OP=59
local pool={}; for i=1,MAX_OP do pool[i]=i end
for i=MAX_OP,2,-1 do local j=math.random(1,i); pool[i],pool[j]=pool[j],pool[i] end
local op2c={}; local c2op={}
for i=1,MAX_OP do op2c[i]=pool[i]; c2op[pool[i]]=i end

local function remap(p)
  for _,ins in ipairs(p.code) do ins.op=op2c[ins.op] or ins.op end
  for _,f in ipairs(p.funcs) do remap(f) end
end
remap(proto)

local function serial(p)
  local kp={}
  for _,c in ipairs(p.consts) do
    if type(c)=="number" then
      if c==math.floor(c) and math.abs(c)<1e12 then kp[#kp+1]=ne(math.floor(c))
      else kp[#kp+1]=tostring(c) end
    elseif type(c)=="string" then kp[#kp+1]=hide_str(c)
    else kp[#kp+1]=tostring(c) end
  end
  local np={}
  for _,n in ipairs(p.names) do np[#np+1]=hide_str(n) end
  local cp={}
  for _,ins in ipairs(p.code) do cp[#cp+1]=("{%s,%s}"):format(ne(ins.op),ne(ins.arg)) end
  local fp={}
  for _,sub in ipairs(p.funcs) do fp[#fp+1]=serial(sub) end
  return ("{k={%s},n={%s},c={%s},f={%s},p=%s}"):format(
    table.concat(kp,","),table.concat(np,","),table.concat(cp,","),
    table.concat(fp,","),ne(p.params or 0))
end

local proto_str=serial(proto)

local UM_parts={}
for k,v in pairs(c2op) do UM_parts[#UM_parts+1]=("[%s]=%s"):format(ne(k),ne(v)) end
local UM_str="{"..table.concat(UM_parts,",").."}"

local function opc(name) return ne(OP[name]) end

local lines={}; local function L(s) lines[#lines+1]=s end

local vUM=V(); local vPR=V(); local vVM=V()
local vF=V(); local vST=V(); local vEN=V(); local vUV=V(); local vPC=V()
local vIN=V(); local vOP=V(); local vAR=V()

-- ★ Lua5.1互換ビット演算ヘルパー関数名
local vBIT=V()

L("(function()")
L(("local %s=%s"):format(vUM,UM_str))
L(("local %s=%s"):format(vPR,proto_str))

-- ★ ビット演算ヘルパー (Lua5.1互換・bit32不使用)
L(("local %s={}"):format(vBIT))
L(("do"):format())
L(("  local function _xor(a,b) local r=0;for i=0,31 do local x=math.floor(a/2^i)%2;local y=math.floor(b/2^i)%2;if x~=y then r=r+2^i end end;return r end"))
L(("  local function _and(a,b) local r=0;for i=0,31 do if math.floor(a/2^i)%2==1 and math.floor(b/2^i)%2==1 then r=r+2^i end end;return r end"))
L(("  local function _or(a,b) local r=0;for i=0,31 do if math.floor(a/2^i)%2==1 or math.floor(b/2^i)%2==1 then r=r+2^i end end;return r end"))
L(("  local function _not(a) local r=0;for i=0,31 do if math.floor(a/2^i)%2==0 then r=r+2^i end end;return r end"))
L(("  local function _shl(a,b) return math.floor(a*(2^b))%4294967296 end"))
L(("  local function _shr(a,b) return math.floor(a/(2^b)) end"))
L(("  %s.bxor=_xor;%s.band=_and;%s.bor=_or;%s.bnot=_not;%s.shl=_shl;%s.shr=_shr"):format(vBIT,vBIT,vBIT,vBIT,vBIT,vBIT))
L("end")

L(("local %s"):format(vVM))
L(("%s=function(%s,%s,%s,%s)"):format(vVM,vF,vST,vEN,vUV))
L(("  %s=%s or {}"):format(vST,vST))
L(("  %s=%s or _G"):format(vEN,vEN))
L(("  %s=%s or {}"):format(vUV,vUV))
L(("  local %s=%s.k"):format("_K",vF))
L(("  local %s=%s.n"):format("_N",vF))
L(("  local %s=1"):format(vPC))
local vSCOPE=V()
L(("  local %s={{}}"):format(vSCOPE))
local vSET_L=V(); local vGET_L=V()
L(("  local function %s(nm,val)"):format(vSET_L))
L(("    for _i=#%s,1,-1 do if %s[_i][nm]~=nil then %s[_i][nm]=val;return end end"):format(vSCOPE,vSCOPE,vSCOPE))
L(("    %s[#%s][nm]=val"):format(vSCOPE,vSCOPE))
L("  end")
L(("  local function %s(nm)"):format(vGET_L))
L(("    for _i=#%s,1,-1 do local v=%s[_i][nm];if v~=nil then return v end end"):format(vSCOPE,vSCOPE))
L("  end")

L("  while true do")
L(("    local %s=%s.c[%s]"):format(vIN,vF,vPC))
L(("    if not %s then break end"):format(vIN))
L(("    local %s=%s[%s[1]]"):format(vOP,vUM,vIN))
L(("    local %s=%s[2]"):format(vAR,vIN))
L(("    %s=%s+1"):format(vPC,vPC))

local function pop_expr() return ("table.remove(%s)"):format(vST) end
local function push_expr(v) return ("%s[#%s+1]=%s"):format(vST,vST,v) end
local function top_expr() return ("%s[#%s]"):format(vST,vST) end

L(("    if %s==%s then %s"):format(vOP,opc("PUSH_NIL"),push_expr("nil")))
L(("    elseif %s==%s then %s"):format(vOP,opc("PUSH_TRUE"),push_expr("true")))
L(("    elseif %s==%s then %s"):format(vOP,opc("PUSH_FALSE"),push_expr("false")))
L(("    elseif %s==%s then %s"):format(vOP,opc("PUSH_NUM"),push_expr("_K["..vAR.."]")))
L(("    elseif %s==%s then %s"):format(vOP,opc("PUSH_STR"),push_expr("_K["..vAR.."]")))
L(("    elseif %s==%s then -- vararg noop"):format(vOP,opc("PUSH_VARARG")))
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
L(("    elseif %s==%s then while #%s<%s do %s end;while #%s>%s do %s end"):format(
  vOP,opc("ADJUST"),vST,vAR,push_expr("nil"),vST,vAR,pop_expr()))
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

-- ★ 算術演算 (Lua5.1互換: &,|,~,<<,>>をヘルパー関数に置き換え)
local function arith(opname, op_sym)
  local va=V(); local vb=V()
  L(("    elseif %s==%s then local %s=%s;local %s=%s;%s"):format(
    vOP,opc(opname),vb,pop_expr(),va,pop_expr(),push_expr(va..op_sym..vb)))
end
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
arith_fn("SHL","shl"); arith_fn("SHR","shr")
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
L(("      local %s={%s(table.unpack and table.unpack(%s) or unpack(%s))}"):format(vres,vfn,vargs,vargs))
L(("      for %s=1,#%s do %s end"):format(vci,vres,push_expr(vres.."["..vci.."]")))

local vrv=V(); local vri=V()
L(("    elseif %s==%s then"):format(vOP,opc("RETURN")))
L(("      local %s={}"):format(vrv))
L(("      for %s=1,%s do table.insert(%s,1,%s) end"):format(vri,vAR,vrv,pop_expr()))
L(("      return table.unpack and table.unpack(%s) or unpack(%s)"):format(vrv,vrv))

local vcls=V(); local vcenv=V()
L(("    elseif %s==%s then"):format(vOP,opc("CLOSURE")))
L(("      local %s=%s.f[%s]"):format(vcls,vF,vAR))
L(("      local %s=%s"):format(vcenv,vEN))
L(("      %s"):format(push_expr("(function(...) local _fa={...}; return "..vVM.."("..vcls..",_fa,"..vcenv..",{}) end)")))

L(("    elseif %s==%s then %s[#%s+1]={}"):format(vOP,opc("ENTER_SCOPE"),vSCOPE,vSCOPE))
L(("    elseif %s==%s then %s[#%s]=nil"):format(vOP,opc("LEAVE_SCOPE"),vSCOPE,vSCOPE))

local vfp_st=V(); local vfp_lim=V(); local vfp_stp=V()
L(("    elseif %s==%s then"):format(vOP,opc("FORPREP")))
L(("      local %s=%s;local %s=%s;local %s=%s"):format(vfp_stp,pop_expr(),vfp_lim,pop_expr(),vfp_st,pop_expr()))
L(("      %s;%s;%s"):format(push_expr(vfp_st),push_expr(vfp_lim),push_expr(vfp_stp)))
L(("      if (%s>0 and %s>%s) or (%s<=0 and %s<%s) then %s=%s+%s end"):format(
  vfp_stp,vfp_st,vfp_lim, vfp_stp,vfp_st,vfp_lim, vPC,vPC,vAR))
local vfl_stp=V(); local vfl_lim=V(); local vfl_v=V()
L(("    elseif %s==%s then"):format(vOP,opc("FORLOOP")))
L(("      local %s=%s[#%s];local %s=%s[#%s-1];local %s=%s[#%s-2]"):format(
  vfl_stp,vST,vST,vfl_lim,vST,vST,vfl_v,vST,vST))
L(("      %s=%s+%s;%s[#%s-2]=%s"):format(vfl_v,vfl_v,vfl_stp,vST,vST,vfl_v))
L(("      if (%s>0 and %s<=%s) or (%s<=0 and %s>=%s) then %s=%s+%s end"):format(
  vfl_stp,vfl_v,vfl_lim, vfl_stp,vfl_v,vfl_lim, vPC,vPC,vAR))

local vgfp_c=V(); local vgfp_s=V(); local vgfp_i=V()
L(("    elseif %s==%s then"):format(vOP,opc("GFORPREP")))
L(("      local %s=%s;local %s=%s;local %s=%s"):format(vgfp_c,pop_expr(),vgfp_s,pop_expr(),vgfp_i,pop_expr()))
L(("      %s;%s;%s"):format(push_expr(vgfp_i),push_expr(vgfp_s),push_expr(vgfp_c)))

local vgfl_c=V(); local vgfl_s=V(); local vgfl_i=V(); local vgfl_r=V(); local vgfl_j=V()
L(("    elseif %s==%s then"):format(vOP,opc("GFORLOOP")))
L(("      local %s=%s[#%s];local %s=%s[#%s-1];local %s=%s[#%s-2]"):format(
  vgfl_c,vST,vST,vgfl_s,vST,vST,vgfl_i,vST,vST))
L(("      local %s={%s(%s,%s)}"):format(vgfl_r,vgfl_i,vgfl_s,vgfl_c))
L(("      if %s[1]~=nil then"):format(vgfl_r))
L(("        %s[#%s]=%s[1]"):format(vST,vST,vgfl_r))
L(("        for %s=#%s,1,-1 do %s end"):format(vgfl_j,vgfl_r,push_expr(vgfl_r.."["..vgfl_j.."]")))
L(("        %s=%s+%s"):format(vPC,vPC,vAR))
L("      end")

L("    end")
L("  end")
L("end")

local vEntry=V()
L(("local %s=function()"):format(vEntry))
L(("  %s(%s,{},_G,{})"):format(vVM,vPR))
L("end")
L(("%s()"):format(vEntry))
L("end)()")

local final=table.concat(lines,"\n")
local fw=io.open(output_file,"w")
if not fw then die("cannot write: "..output_file) end
fw:write(final); fw:close()
io.stderr:write("VM_OBF_INFO: done! "..output_file.."\n")
io.write("OK:"..output_file)
