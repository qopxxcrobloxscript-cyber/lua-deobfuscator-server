// vm/weredevs/opcodeMap.js
'use strict';

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
function buildOpcodeMapFromTrace(vmTraceEntries, bTableInstructions) {
  if (!vmTraceEntries || vmTraceEntries.length === 0)
    return { opcodeMap: {}, remapped: false, method: 'trace_build' };

  // 頻度カウント (l フィールドを使用)
  const freq = {};
  for (const e of vmTraceEntries) {
    const op = e.l !== null && e.l !== undefined ? e.l : e.op;
    if (op === null || op === undefined) continue;
    const k = String(op);
    freq[k] = (freq[k] || 0) + 1;
  }

  const sorted = Object.entries(freq)
    .sort((a, b) => b[1] - a[1])
    .map(([k, count]) => ({ opcode: isNaN(Number(k)) ? k : parseInt(k), count }));

  // bTableInstructions が存在すれば命令構造から opcode を推定
  const opcodeMap = {};
  if (bTableInstructions && bTableInstructions.length > 0) {
    // B テーブルの各命令の op フィールドと、対応する trace 上の l を突き合わせ
    for (const inst of bTableInstructions.slice(0, 200)) {
      const op = inst.op;
      if (op === null || op === undefined) continue;
      const lua51Name = LUA51_OPCODES[op];
      if (lua51Name) opcodeMap[String(op)] = lua51Name;
    }
  }

  // 頻度が高い opcode を Lua5.1 標準 opcode にヒューリスティックマッピング
  // MOVE(0), LOADK(1), RETURN(30) などは出現頻度パターンが特徴的
  const heuristic = {
    RETURN: null, CALL: null, MOVE: null, LOADK: null,
    GETGLOBAL: null, SETGLOBAL: null, JMP: null,
  };
  // 最頻出 top3 を CALL/MOVE/LOADK に割り当て（確率的）
  for (let i = 0; i < Math.min(3, sorted.length); i++) {
    const names = ['CALL', 'MOVE', 'LOADK'];
    if (!(String(sorted[i].opcode) in opcodeMap)) {
      heuristic[names[i]] = sorted[i].opcode;
      opcodeMap[String(sorted[i].opcode)] = names[i];
    }
  }

  return { opcodeMap, sorted, heuristic, remapped: Object.keys(opcodeMap).length > 0, method: 'trace_build' };
}

// ── 項目 10: remapOpcodes — vmhookログのopcode順序でVMテーブルを再マッピング ──
// Weredev は opcode 番号をランダムシャッフルすることがある。
// trace の実行順序と既知の Lua5.1 意味論を使って再マッピングを試みる。
function remapOpcodes(vmTraceEntries, knownOpcodeMap) {
  if (!vmTraceEntries || vmTraceEntries.length === 0)
    return { remapped: {}, confidence: 0, method: 'remap_opcodes' };

  const known  = knownOpcodeMap || {};
  const remapped = { ...known };
  let   mapped   = Object.keys(remapped).length;

  // 実行コンテキストから opcode 意味を推定
  // レジスタ変化 + operand パターンで判定
  const candidates = {};
  for (let i = 0; i < Math.min(vmTraceEntries.length, 5000); i++) {
    const e   = vmTraceEntries[i];
    const op  = String(e.l !== undefined ? e.l : e.op);
    const A   = e.A !== undefined ? e.A : e.a;
    const B   = e.B !== undefined ? e.B : e.b;
    const C   = e.C !== undefined ? e.C : e.c;
    if (op === 'null' || op === 'undefined') continue;
    if (op in remapped) continue;  // 既知ならスキップ

    if (!candidates[op]) candidates[op] = { votes: {}, count: 0, samples: [] };
    candidates[op].count++;
    if (candidates[op].samples.length < 5) candidates[op].samples.push({ A, B, C });

    // 推論ルール
    // A=小, B=小, C=null → MOVE候補
    if (typeof A === 'number' && typeof B === 'number' && (C === null || C === undefined) && A < 256 && B < 256)
      candidates[op].votes['MOVE'] = (candidates[op].votes['MOVE'] || 0) + 1;
    // A=小, B=大(定数インデックス), C=null → LOADK候補
    if (typeof A === 'number' && typeof B === 'number' && B > 100 && (C === null || C === undefined))
      candidates[op].votes['LOADK'] = (candidates[op].votes['LOADK'] || 0) + 1;
    // A=0, B=1以下, C=0 → RETURN候補
    if (A === 0 && (B === 0 || B === 1) && (C === null || C === 0))
      candidates[op].votes['RETURN'] = (candidates[op].votes['RETURN'] || 0) + 1;
    // A=小, B=小, C=小 (3オペランド) → CALL/ADD/SUB 候補
    if (typeof A === 'number' && typeof B === 'number' && typeof C === 'number' && A < 64 && B < 64 && C < 64)
      candidates[op].votes['CALL'] = (candidates[op].votes['CALL'] || 0) + 1;
  }

  // 各候補に対して最多投票の名前を採用
  const usedNames = new Set(Object.values(remapped));
  for (const [op, info] of Object.entries(candidates)) {
    const best = Object.entries(info.votes).sort((a,b) => b[1]-a[1])[0];
    if (!best) continue;
    const [name, votes] = best;
    if (!usedNames.has(name) && votes >= 3) {
      remapped[op] = name + '_inferred';
      usedNames.add(name);
      mapped++;
    }
  }

  const confidence = Math.min(100, Math.round((mapped / 38) * 100));
  return { remapped, mapped, total: 38, confidence, candidates: Object.keys(candidates).length, method: 'remap_opcodes' };
}

// ── 項目 5/6: while true do / while 1 do 検出 + vmDecompileInstruction ──
// VM ディスパッチループ検出
function vmDecompileInstruction(opName, pc, A, B, C, opcodeMapExt) {
  const map = opcodeMapExt || LUA51_OPCODES;
  const r   = (n) => n !== null && n !== undefined ? `v${n}` : '_';
  const resolvedName = typeof opName === 'number'
    ? (map[String(opName)] || `OP_${opName}`) : (opName || 'UNKNOWN');

  switch (resolvedName) {
    case 'MOVE':      return `${r(A)} = ${r(B)}`;
    case 'LOADK':     return `${r(A)} = K[${B}]`;
    case 'LOADBOOL':  return `${r(A)} = ${B ? 'true' : 'false'}${C ? '; pc=pc+1' : ''}`;
    case 'LOADNIL':   return `${r(A)}..${r(B)} = nil`;
    case 'GETUPVAL':  return `${r(A)} = UpValue[${B}]`;
    case 'GETGLOBAL': return `${r(A)} = _G[K[${B}]]`;
    case 'SETGLOBAL': return `_G[K[${B}]] = ${r(A)}`;
    case 'GETTABLE':  return `${r(A)} = ${r(B)}[RK(${C})]`;
    case 'SETTABLE':  return `${r(A)}[RK(${B})] = RK(${C})`;
    case 'NEWTABLE':  return `${r(A)} = {} -- size B=${B} C=${C}`;
    case 'SELF':      return `${r(A+1)} = ${r(B)}; ${r(A)} = ${r(B)}[RK(${C})]`;
    case 'ADD':       return `${r(A)} = RK(${B}) + RK(${C})`;
    case 'SUB':       return `${r(A)} = RK(${B}) - RK(${C})`;
    case 'MUL':       return `${r(A)} = RK(${B}) * RK(${C})`;
    case 'DIV':       return `${r(A)} = RK(${B}) / RK(${C})`;
    case 'MOD':       return `${r(A)} = RK(${B}) % RK(${C})`;
    case 'POW':       return `${r(A)} = RK(${B}) ^ RK(${C})`;
    case 'UNM':       return `${r(A)} = -${r(B)}`;
    case 'NOT':       return `${r(A)} = not ${r(B)}`;
    case 'LEN':       return `${r(A)} = #${r(B)}`;
    case 'CONCAT': {
      const parts = [];
      for (let i = B; i <= C; i++) parts.push(r(i));
      return `${r(A)} = ${parts.join(' .. ')}`;
    }
    case 'JMP':       return `pc = pc + ${B + 1}  -- jump to ${pc + 1 + B}`;
    case 'EQ':        return `if (RK(${B}) == RK(${C})) ~= ${A?'true':'false'} then pc=pc+1 end`;
    case 'LT':        return `if (RK(${B}) < RK(${C})) ~= ${A?'true':'false'} then pc=pc+1 end`;
    case 'LE':        return `if (RK(${B}) <= RK(${C})) ~= ${A?'true':'false'} then pc=pc+1 end`;
    case 'TEST':      return `if not ${r(A)} then pc=pc+1 end`;
    case 'TESTSET':   return `if ${r(B)} then ${r(A)} = ${r(B)} else pc=pc+1 end`;
    case 'CALL': {
      const nargs = (B || 1) - 1;
      const nret  = (C || 1) - 1;
      const args_ = Array.from({length: nargs}, (_, i) => r(A + 1 + i));
      const rets  = Array.from({length: Math.max(1,nret)}, (_, i) => r(A + i));
      return `${rets.join(', ')} = ${r(A)}(${args_.join(', ')})`;
    }
    case 'TAILCALL': {
      const nargs_ = (B || 1) - 1;
      const args__ = Array.from({length: nargs_}, (_, i) => r(A + 1 + i));
      return `return ${r(A)}(${args__.join(', ')})`;
    }
    case 'RETURN': {
      if (!A && !B) return 'return';
      const nv  = (B || 1) - 1;
      const vs  = Array.from({length: Math.max(1,nv)}, (_, i) => r((A||0) + i));
      return `return ${vs.join(', ')}`;
    }
    case 'FORPREP':  return `${r(A)} = ${r(A)} - ${r(A+2)}; goto forloop_${pc+1+B}`;
    case 'FORLOOP':  return `${r(A)} += ${r(A+2)}; if ${r(A)} <= ${r(A+1)} then goto forloop_${pc+1+B} end`;
    case 'TFORLOOP': return `${r(A+2)}..${r(A+2+(C||1))} = ${r(A)}(${r(A+1)}, ${r(A+2)}); if ${r(A+2)} ~= nil then ${r(A+1)} = ${r(A+2)} end`;
    case 'SETLIST':  return `${r(A)}[${((C||1)-1)*50+1}..] = ${r(A+1)}..${r(A+B)}`;
    case 'CLOSE':    return `close upvalues ${r(A)}..top`;
    case 'CLOSURE':  return `${r(A)} = closure(Proto[${B}])`;
    case 'VARARG': {
      const nva = (B || 1) - 1;
      const vas = Array.from({length: Math.max(1,nva)}, (_, i) => r((A||0)+i));
      return `${vas.join(', ')} = ...`;
    }
    default:
      return `-- ${resolvedName}(A=${A}, B=${B}, C=${C})`;
  }
}

// ── 項目 7: VM解析に maxInstructions=100000 ガードを適用した weredevAnalyze ──
function assignWeredevOpcodes(dispatchBlocks) {
  const sortedT = [...new Set(dispatchBlocks.map(b => b.threshold))].sort((a, b) => a - b);
  return dispatchBlocks.map((block, idx) => ({
    ...block,
    opcodeMin: idx === 0 ? 0 : sortedT[idx - 1],
    opcodeMax: block.threshold - 1,
    estimatedOpcode: sortedT[idx] !== undefined ? sortedT[idx] - 1 : idx,
    idx,
  }));
}

// ────────────────────────────────────────────────────────────────────────
//  Step 5: opcodeブロック意味解析
// ────────────────────────────────────────────────────────────────────────
function _inferOpNameFromOperands(operands, body, ctx) {
  const rV  = (ctx && ctx.regVar) || 'V';
  const zFn = (ctx && ctx.zFunc)  || 'Z';
  const rE  = _wdEscapeRegex;
  const { A, B, C, _op } = operands;

  // RETURN
  if (/\breturn\b/.test(body) && !/function/.test(body)) return 'RETURN';

  // CALL: V[A](...)
  if (body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*\\([^)]*\\)(?!\\s*[\\[.])`)) &&
      !body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*=\\s*${rE(rV)}\\s*\\[\\d+\\]\\s*\\[`))) {
    // 戻り値ありなら CALL_RET、なければ CALL
    if (body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*=\\s*${rE(rV)}\\s*\\[\\d+\\]\\s*\\(`))) return 'CALL';
    return 'CALL';
  }

  // NEWTABLE
  if (body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*=\\s*\\{\\s*\\}`))) return 'NEWTABLE';

  // 算術演算子から直接判定
  if (_op) {
    return {'+':'ADD','-':'SUB','*':'MUL','/':'DIV','%':'MOD','^':'POW'}[_op] || 'ADD';
  }

  // CONCAT (..)
  if (body.includes('..')) return 'CONCAT';

  // UNM: V[A] = -V[B]
  if (body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*=\\s*-${rE(rV)}\\s*\\[\\d+\\]`))) return 'UNM';
  // NOT
  if (body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*=\\s*not\\s+${rE(rV)}\\s*\\[\\d+\\]`))) return 'NOT';
  // LEN
  if (body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*=\\s*#${rE(rV)}\\s*\\[\\d+\\]`))) return 'LEN';

  // SETTABLE: V[A][key] = V[C]
  if (body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*\\[`)) &&
      body.match(new RegExp(`\\]\\s*=\\s*${rE(rV)}\\s*\\[`))) {
    // 左辺が V[A][key] = の形か
    if (body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*\\[[^\\]]+\\]\\s*=`))) return 'SETTABLE';
  }

  // GETTABLE: V[A] = V[B][...]
  if (body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*=\\s*${rE(rV)}\\s*\\[\\d+\\]\\s*\\[`))) return 'GETTABLE';

  // LOADK: V[A] = Z(B) or V[A] = R[B]
  if (body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*=\\s*${rE(zFn)}\\s*\\(\\d+\\)`)) ||
      body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*=\\s*[A-Za-z_]\\w*\\s*\\[\\d+\\](?!\\s*\\[)`))) {
    // Z() or pool[] → LOADK
    if (body.match(new RegExp(`${rE(zFn)}\\s*\\(\\d+\\)`))) return 'LOADK';
  }

  // GETGLOBAL / SETGLOBAL
  if (body.includes('_ENV') || body.includes('_G')) {
    if (body.match(/=\s*(?:_ENV|_G)\[/)) return 'GETGLOBAL';
    if (body.match(/(?:_ENV|_G)\[[^\]]+\]\s*=/)) return 'SETGLOBAL';
  }

  // MOVE: V[A] = V[B]  (シンプルなレジスタ転送)
  if (A !== null && B !== null && C === null &&
      body.match(new RegExp(`${rE(rV)}\\s*\\[\\d+\\]\\s*=\\s*${rE(rV)}\\s*\\[\\d+\\](?!\\s*[+\\-*/%^\\[\\.])`))) {
    return 'MOVE';
  }

  // JMP: pc = pc + N
  if (body.match(/\bpc\s*=\s*pc\s*[+\-]\s*\d+/)) return 'JMP';

  // 不明
  return `OP_UNKNOWN`;
}
function resolveInstrConstants(instrLua, flatPool) {
  if (!instrLua || !flatPool) return instrLua;
  // K[N] 形式の参照を解決 (vmDecompileInstruction出力に含まれる)
  return instrLua.replace(/K\[(\d+)\]/g, (match, idxStr) => {
    const idx = parseInt(idxStr);
    // flatPoolの最初のエントリから取得
    for (const acc of Object.values(flatPool)) {
      const realIdx = idx - acc.offset;
      const elem = acc.elements[realIdx - 1];
      if (!elem) continue;
      if (elem.type === 'string') {
        const safe = elem.value.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n');
        return `"${safe}"`;
      }
      if (elem.type === 'number') return String(elem.value);
      if (elem.type === 'bool')   return String(elem.value);
      if (elem.type === 'nil')    return 'nil';
    }
    return match; // 解決できなければそのまま
  });
}

// APIハンドラ

module.exports = {
  LUA51_OPCODES, OPCODE_CATEGORIES,
  vmTraceAnalyzer, buildOpcodeMapFromTrace, remapOpcodes,
  vmDecompileInstruction, assignWeredevOpcodes,
  _inferOpNameFromOperands, resolveInstrConstants,
};
