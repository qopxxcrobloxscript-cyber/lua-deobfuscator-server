// vm/weredevs/opcodeMap.js
'use strict';

// ────────────────────────────────────────────────────────────────────────
//  LUA51_OPCODES — 参照用として残すが、実行時には使用しない
//  項目5: 静的マップは直接ディスパッチに使用せず、
//         buildOpcodeMapFromTrace() による実行順再構築を必ず経由する
// ────────────────────────────────────────────────────────────────────────
const LUA51_OPCODES = {
  0:'MOVE',   1:'LOADK',    2:'LOADBOOL', 3:'LOADNIL',  4:'GETUPVAL',
  5:'GETGLOBAL',6:'GETTABLE',7:'SETGLOBAL',8:'SETUPVAL', 9:'SETTABLE',
  10:'NEWTABLE',11:'SELF',  12:'ADD',     13:'SUB',     14:'MUL',
  15:'DIV',   16:'MOD',     17:'POW',     18:'UNM',     19:'NOT',
  20:'LEN',   21:'CONCAT',  22:'JMP',     23:'EQ',      24:'LT',
  25:'LE',    26:'TEST',    27:'TESTSET', 28:'CALL',    29:'TAILCALL',
  30:'RETURN',31:'FORLOOP', 32:'FORPREP', 33:'TFORLOOP',34:'SETLIST',
  35:'CLOSE', 36:'CLOSURE', 37:'VARARG',
};

const OPCODE_CATEGORIES = {
  MOVE:'MOVE',    LOADK:'CONST',   LOADBOOL:'CONST', LOADNIL:'CONST',
  GETUPVAL:'LOAD',GETGLOBAL:'LOAD',GETTABLE:'LOAD',
  SETGLOBAL:'STORE',SETUPVAL:'STORE',SETTABLE:'STORE',
  NEWTABLE:'TABLE',SELF:'TABLE',
  ADD:'ARITH',SUB:'ARITH',MUL:'ARITH',DIV:'ARITH',MOD:'ARITH',POW:'ARITH',
  UNM:'ARITH',NOT:'ARITH',LEN:'ARITH',CONCAT:'ARITH',
  JMP:'JUMP',EQ:'JUMP',LT:'JUMP',LE:'JUMP',TEST:'JUMP',TESTSET:'JUMP',
  CALL:'CALL',TAILCALL:'CALL',RETURN:'RETURN',
  FORLOOP:'LOOP',FORPREP:'LOOP',TFORLOOP:'LOOP',
  SETLIST:'TABLE',CLOSE:'CLOSE',CLOSURE:'CLOSURE',VARARG:'VARARG',
};

// ────────────────────────────────────────────────────────────────────────
//  項目5: buildOpcodeMapFromTrace — VMhook実行ログから opcode を再構築
//
//  処理方針:
//   1. vmhook トレースの実行順序を解析
//   2. bTable 命令との照合でopName を確定
//   3. 頻度 + オペランドパターンでヒューリスティック補完
//   4. 静的 LUA51_OPCODES には一切依存しない
// ────────────────────────────────────────────────────────────────────────
function buildOpcodeMapFromTrace(vmTraceEntries, bTableInstructions) {
  if (!vmTraceEntries || vmTraceEntries.length === 0)
    return { opcodeMap: {}, remapped: false, source: 'empty', method: 'trace_build' };

  // Step 1: 実行順カウント
  const freq       = {};
  const execSeq    = [];   // 実行順 opcode 配列
  const opContexts = {};   // opcode ごとのオペランド履歴

  for (const e of vmTraceEntries) {
    const op = e.l !== undefined ? e.l : e.op;
    if (op === null || op === undefined) continue;
    const k  = String(op);
    const A  = e.A !== undefined ? e.A : e.arg1;
    const B  = e.B !== undefined ? e.B : e.arg2;
    const C  = e.C !== undefined ? e.C : e.arg3;

    freq[k] = (freq[k] || 0) + 1;
    execSeq.push(op);

    if (!opContexts[k]) opContexts[k] = { samples: [], totalA: 0, totalB: 0, totalC: 0, count: 0 };
    if (opContexts[k].samples.length < 10) opContexts[k].samples.push({ A, B, C });
    if (typeof A === 'number') opContexts[k].totalA += A;
    if (typeof B === 'number') opContexts[k].totalB += B;
    if (typeof C === 'number') opContexts[k].totalC += C;
    opContexts[k].count++;
  }

  const sortedByFreq = Object.entries(freq).sort((a, b) => b[1] - a[1]);

  // Step 2: bTable 命令との照合（最優先 — 直接一致）
  const confirmed = {};
  if (bTableInstructions && bTableInstructions.length > 0) {
    for (const inst of bTableInstructions.slice(0, 1000)) {
      if (inst.opName && inst.op !== undefined) {
        confirmed[String(inst.op)] = inst.opName;
      }
    }
  }

  // Step 3: オペランドパターンによる推論
  //   - A=0..255, B=0..255, C=null → MOVE
  //   - A=*, B=large(>100), C=null → LOADK
  //   - A=0, B=0|1, C=null        → RETURN
  //   - 連続呼び出しで大きなBを持つ → GETGLOBAL
  //   - C が頻繁に非null           → CALL / ARITH
  const inferred = {};
  const usedNames = new Set(Object.values(confirmed));

  const INFER_RULES = [
    { name: 'RETURN',    test: (ctx) => ctx.samples.some(s => s.A === 0 && (s.B === 0 || s.B === 1) && !s.C) },
    { name: 'MOVE',      test: (ctx) => ctx.count >= 5 && ctx.samples.every(s => typeof s.A === 'number' && typeof s.B === 'number' && !s.C) },
    { name: 'LOADK',     test: (ctx) => ctx.samples.some(s => typeof s.B === 'number' && s.B > 100 && !s.C) },
    { name: 'JMP',       test: (ctx) => ctx.samples.some(s => s.A === 0 && typeof s.B === 'number' && !s.C) },
    { name: 'CALL',      test: (ctx) => ctx.samples.some(s => typeof s.A === 'number' && typeof s.B === 'number' && typeof s.C === 'number') },
    { name: 'GETGLOBAL', test: (ctx) => ctx.samples.some(s => typeof s.B === 'number' && s.B > 50 && !s.C) },
    { name: 'SETGLOBAL', test: (ctx) => ctx.samples.some(s => typeof s.B === 'number' && s.B > 50 && !s.C) && ctx.count >= 2 },
  ];

  for (const [opKey, ctx] of Object.entries(opContexts)) {
    if (opKey in confirmed) continue;
    for (const rule of INFER_RULES) {
      if (!usedNames.has(rule.name) && rule.test(ctx)) {
        inferred[opKey] = rule.name + '_inferred';
        usedNames.add(rule.name);
        break;
      }
    }
  }

  // Step 4: マージ（confirmed > inferred）
  const opcodeMap = { ...inferred, ...confirmed };

  const confidence = Object.keys(confirmed).length > 0
    ? Math.min(95, 40 + Object.keys(confirmed).length * 5)
    : Math.min(35, Object.keys(inferred).length * 5);

  return {
    opcodeMap,
    confirmed,
    inferred,
    frequency:  sortedByFreq.slice(0, 20),
    execLength: execSeq.length,
    source:     Object.keys(confirmed).length > 0 ? 'btable_confirmed' : 'heuristic_only',
    remapped:   Object.keys(opcodeMap).length > 0,
    confidence,
    method:     'trace_build',
  };
}

// ────────────────────────────────────────────────────────────────────────
//  remapOpcodes — トレース実行順序で VM テーブルを再マッピング
//  項目5: 静的マップ参照なし・実行ログベース
// ────────────────────────────────────────────────────────────────────────
function remapOpcodes(vmTraceEntries, knownOpcodeMap) {
  if (!vmTraceEntries || vmTraceEntries.length === 0)
    return { remapped: {}, confidence: 0, method: 'remap_opcodes' };

  // knownOpcodeMap は buildOpcodeMapFromTrace の出力を想定
  const base     = (knownOpcodeMap && knownOpcodeMap.opcodeMap) || knownOpcodeMap || {};
  const remapped = { ...base };
  const usedNames = new Set(Object.values(remapped).map(n => n.replace('_inferred', '')));
  let mapped = Object.keys(remapped).length;

  // 追加推論: トレース内の operand パターンで未割当 opcode を補完
  const candidates = {};
  for (let i = 0; i < Math.min(vmTraceEntries.length, 5000); i++) {
    const e  = vmTraceEntries[i];
    const op = String(e.l !== undefined ? e.l : e.op);
    const A  = e.A !== undefined ? e.A : e.arg1;
    const B  = e.B !== undefined ? e.B : e.arg2;
    const C  = e.C !== undefined ? e.C : e.arg3;
    if (op in remapped) continue;

    if (!candidates[op]) candidates[op] = { votes: {}, count: 0 };
    candidates[op].count++;

    if (typeof A === 'number' && typeof B === 'number' && C === null && A < 256 && B < 256)
      candidates[op].votes['MOVE'] = (candidates[op].votes['MOVE'] || 0) + 1;
    if (typeof B === 'number' && B > 100 && C === null)
      candidates[op].votes['LOADK'] = (candidates[op].votes['LOADK'] || 0) + 1;
    if (A === 0 && (B === 0 || B === 1) && (C === null || C === 0))
      candidates[op].votes['RETURN'] = (candidates[op].votes['RETURN'] || 0) + 1;
    if (typeof C === 'number' && C !== null)
      candidates[op].votes['CALL'] = (candidates[op].votes['CALL'] || 0) + 1;
  }

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
  return { remapped, mapped, total: 38, confidence, method: 'remap_opcodes' };
}

// ────────────────────────────────────────────────────────────────────────
//  vmTraceAnalyzer — トレース統計解析
// ────────────────────────────────────────────────────────────────────────
function vmTraceAnalyzer(vmTrace) {
  if (!vmTrace || vmTrace.length === 0)
    return { success: false, error: 'vmTraceが空', opcodeMap: {} };

  const freq = {};
  for (const e of vmTrace) {
    const k = String(e.op !== undefined ? e.op : e.l);
    if (k === 'null' || k === 'undefined') continue;
    freq[k] = (freq[k] || 0) + 1;
  }
  const sorted = Object.entries(freq)
    .sort((a, b) => b[1] - a[1])
    .map(([op, count]) => ({ op: isNaN(Number(op)) ? op : parseInt(op), count }));

  // 項目5: 実行順ベースで opcodeMap を構築（静的 LUA51_OPCODES には依存しない）
  const traceResult   = buildOpcodeMapFromTrace(vmTrace, []);
  const dispatchTable = traceResult.opcodeMap;

  const opcodeExecutionMap = {};
  for (const [num, name] of Object.entries(dispatchTable)) {
    const cleanName = name.replace('_inferred', '').replace('_heuristic', '');
    const entries   = vmTrace.filter(t => String(t.op) === String(num) || String(t.l) === String(num));
    if (entries.length > 0) {
      opcodeExecutionMap[cleanName] = {
        opcode:    parseInt(num),
        count:     entries.length,
        category:  OPCODE_CATEGORIES[cleanName] || 'UNKNOWN',
        sampleArgs: entries.slice(0, 3).map(e => [e.arg1 ?? e.A, e.arg2 ?? e.B, e.arg3 ?? e.C]),
      };
    }
  }

  const behaviorSummary = {};
  for (const info of Object.values(opcodeExecutionMap)) {
    const cat = info.category;
    behaviorSummary[cat] = (behaviorSummary[cat] || 0) + info.count;
  }

  const ipJumps = [];
  for (let i = 1; i < vmTrace.length; i++) {
    const d = vmTrace[i].ip - vmTrace[i-1].ip;
    if (d !== 1 && d !== 0) ipJumps.push({ from: vmTrace[i-1].ip, to: vmTrace[i].ip, delta: d });
  }

  return {
    success: true,
    totalInstructions: vmTrace.length,
    uniqueOpcodes:     sorted.length,
    opcodeFrequency:   sorted.slice(0, 20),
    opcodeMap:         { map: dispatchTable, opcodeExecutionMap },
    dispatchTable,
    behaviorSummary,
    ipJumps:           ipJumps.slice(0, 30),
    traceSource:       traceResult.source,
    traceConfidence:   traceResult.confidence,
    method:            'vm_trace_analyze',
  };
}

// ────────────────────────────────────────────────────────────────────────
//  vmDecompileInstruction — 単一命令を疑似 Lua 文に変換
// ────────────────────────────────────────────────────────────────────────
function vmDecompileInstruction(opName, pc, A, B, C, opcodeMapExt) {
  // 項目5: opcodeMapExt は実行ログ由来のマップを渡す想定（静的LUA51_OPCODESは最終フォールバック）
  const resolvedName = _resolveOpName(opName, opcodeMapExt);
  const r = (n) => n !== null && n !== undefined ? `v${n}` : '_';

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
    case 'JMP':       return `pc = pc + ${(B||0) + 1}  -- jump to ${pc + 1 + (B||0)}`;
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
      const nv = (B || 1) - 1;
      const vs = Array.from({length: Math.max(1,nv)}, (_, i) => r((A||0) + i));
      return `return ${vs.join(', ')}`;
    }
    case 'FORPREP':  return `${r(A)} = ${r(A)} - ${r(A+2)}; goto forloop_${pc+1+(B||0)}`;
    case 'FORLOOP':  return `${r(A)} += ${r(A+2)}; if ${r(A)} <= ${r(A+1)} then goto forloop_${pc+1+(B||0)} end`;
    case 'TFORLOOP': return `${r(A+2)}..${r(A+2+(C||1))} = ${r(A)}(${r(A+1)}, ${r(A+2)}); if ${r(A+2)} ~= nil then ${r(A+1)} = ${r(A+2)} end`;
    case 'SETLIST':  return `${r(A)}[${((C||1)-1)*50+1}..] = ${r(A+1)}..${r(A+(B||0))}`;
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

function _resolveOpName(opName, ext) {
  if (typeof opName === 'string') {
    const clean = opName.replace('_inferred','').replace('_heuristic','');
    if (clean in OPCODE_CATEGORIES) return clean;
  }
  if (typeof opName === 'number' || (typeof opName === 'string' && !isNaN(Number(opName)))) {
    const k = String(opName);
    if (ext && ext[k]) return ext[k].replace('_inferred','').replace('_heuristic','');
    // 最終フォールバック: LUA51_OPCODES（静的マップだが解決できない場合のみ）
    if (LUA51_OPCODES[k]) return LUA51_OPCODES[k];
  }
  return typeof opName === 'string' ? opName : `OP_${opName}`;
}

// ────────────────────────────────────────────────────────────────────────
//  assignWeredevOpcodes — dispatch ブロック列に opcode 番号を割り当て
// ────────────────────────────────────────────────────────────────────────
function assignWeredevOpcodes(dispatchBlocks) {
  const sortedT = [...new Set(dispatchBlocks.map(b => b.threshold))].sort((a, b) => a - b);
  return dispatchBlocks.map((block, idx) => ({
    ...block,
    opcodeMin:       idx === 0 ? 0 : sortedT[idx - 1],
    opcodeMax:       block.threshold - 1,
    estimatedOpcode: sortedT[idx] !== undefined ? sortedT[idx] - 1 : idx,
    idx,
  }));
}

// ────────────────────────────────────────────────────────────────────────
//  _inferOpNameFromOperands — オペランドパターンから opName を推定
// ────────────────────────────────────────────────────────────────────────
function _inferOpNameFromOperands(operands, body, ctx) {
  const rV  = (ctx && ctx.regVar) || 'V';
  const zFn = (ctx && ctx.zFunc)  || 'Z';
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const { A, B, C, _op } = operands;

  if (/\breturn\b/.test(body) && !/function/.test(body)) return 'RETURN';
  if (body.match(new RegExp(`${esc(rV)}\\[\\d+\\]\\s*=\\s*\\{\\s*\\}`))) return 'NEWTABLE';
  if (_op) return {'+':'ADD','-':'SUB','*':'MUL','/':'DIV','%':'MOD','^':'POW'}[_op] || 'ADD';
  if (body.includes('..')) return 'CONCAT';
  if (body.match(new RegExp(`${esc(rV)}\\[\\d+\\]\\s*=\\s*-${esc(rV)}\\[\\d+\\]`))) return 'UNM';
  if (body.match(new RegExp(`${esc(rV)}\\[\\d+\\]\\s*=\\s*not\\s+${esc(rV)}\\[\\d+\\]`))) return 'NOT';
  if (body.match(new RegExp(`${esc(rV)}\\[\\d+\\]\\s*=\\s*#${esc(rV)}\\[\\d+\\]`))) return 'LEN';
  if (body.match(new RegExp(`${esc(rV)}\\[\\d+\\]\\[`)) &&
      body.match(new RegExp(`\\]\\s*=\\s*${esc(rV)}\\[`)) &&
      body.match(new RegExp(`${esc(rV)}\\[\\d+\\]\\[[^\\]]+\\]\\s*=`))) return 'SETTABLE';
  if (body.match(new RegExp(`${esc(rV)}\\[\\d+\\]\\s*=\\s*${esc(rV)}\\[\\d+\\]\\[`))) return 'GETTABLE';
  if (body.match(new RegExp(`${esc(zFn)}\\s*\\(\\d+\\)`))) return 'LOADK';
  if (body.includes('_ENV') || body.includes('_G')) {
    if (body.match(/=\s*(?:_ENV|_G)\[/)) return 'GETGLOBAL';
    if (body.match(/(?:_ENV|_G)\[[^\]]+\]\s*=/)) return 'SETGLOBAL';
  }
  if (A !== null && B !== null && C === null &&
      body.match(new RegExp(`${esc(rV)}\\[\\d+\\]\\s*=\\s*${esc(rV)}\\[\\d+\\](?!\\s*[+\\-*/%^\\[\\.])`))) return 'MOVE';
  if (body.match(/\bpc\s*=\s*pc\s*[+\-]\s*\d+/)) return 'JMP';
  if (body.match(new RegExp(`${esc(rV)}\\[\\d+\\]\\s*\\([^)]*\\)`))) return 'CALL';
  return 'OP_UNKNOWN';
}

// ────────────────────────────────────────────────────────────────────────
//  resolveInstrConstants — K[N] を実際の定数値で置換
// ────────────────────────────────────────────────────────────────────────
function resolveInstrConstants(instrLua, flatPool) {
  if (!instrLua || !flatPool) return instrLua;
  return instrLua.replace(/K\[(\d+)\]/g, (match, idxStr) => {
    const idx = parseInt(idxStr);
    for (const acc of Object.values(flatPool)) {
      const realIdx = idx - acc.offset;
      const elem    = acc.elements[realIdx - 1];
      if (!elem) continue;
      if (elem.type === 'string') {
        const safe = elem.value.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n');
        return `"${safe}"`;
      }
      if (elem.type === 'number') return String(elem.value);
      if (elem.type === 'bool')   return String(elem.value);
      if (elem.type === 'nil')    return 'nil';
    }
    return match;
  });
}

module.exports = {
  LUA51_OPCODES,
  OPCODE_CATEGORIES,
  vmTraceAnalyzer,
  buildOpcodeMapFromTrace,
  remapOpcodes,
  vmDecompileInstruction,
  assignWeredevOpcodes,
  _inferOpNameFromOperands,
  resolveInstrConstants,
};
