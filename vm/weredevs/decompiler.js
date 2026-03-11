// vm/weredevs/decompiler.js
'use strict';

const fs   = require('fs');
const path = require('path');

const { LUA51_OPCODES, vmDecompileInstruction, vmTraceAnalyzer,
         buildOpcodeMapFromTrace, remapOpcodes, assignWeredevOpcodes,
         _inferOpNameFromOperands, resolveInstrConstants } = require('./opcodeMap');
const { extractWeredevConstPool, extractWeredevZAccessor,
         extractWeredevDispatchLoop, _wdEscapeRegex,
         extractVmTableNames, extractVmTable } = require('./extractor');
const { detectWeredevContext, analyzeWeredevOpcodeBlock,
         extractWeredevOperands, _buildFlatConstPool,
         resolveWeredevZCalls, detectVmDispatchLoop,
         dynamicOpcodeResolver, MAX_DISPATCH_ITERATIONS } = require('./interpreterParser');
const { unwrapVmWrapper, removeConstDecodeLoop } = require('../../utils/luaPrinter');
const { isWeredevObfuscated } = require('../../core/detector');

// ────────────────────────────────────────────────────────────────────────
//  tempDir (decompiled_*.lua 保存用)
// ────────────────────────────────────────────────────────────────────────
const tempDir = path.join(__dirname, '..', '..', 'temp');
try { if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true }); } catch {}

// ════════════════════════════════════════════════════════════════════════
//  項目7: dispatcherFlatten — state-machine を直線命令列へ変換
//
//  入力: extractWeredevDispatchLoop() が返す loops 配列
//  出力: 命令番号順にソートされたフラット命令列 FlatInstr[]
// ════════════════════════════════════════════════════════════════════════
function dispatcherFlatten(loops) {
  const flat = [];
  for (const loop of loops) {
    const blocks = loop.dispatchBlocks || loop.blocks || [];
    // 既に _expandDispatcher 済みの場合は flatInstructions を優先
    if (loop.flatInstructions && loop.flatInstructions.length > 0) {
      flat.push(...loop.flatInstructions);
      continue;
    }
    // threshold 順にソートして直線命令列化
    const sorted = [...blocks].sort((a, b) => (a.threshold || 0) - (b.threshold || 0));
    for (let i = 0; i < sorted.length; i++) {
      const b = sorted[i];
      flat.push({
        opcode:    b.estimatedOpcode !== undefined ? b.estimatedOpcode : i,
        threshold: b.threshold || i,
        body:      b.body || b.rawBody || '',
        loopVar:   loop.loopVar,
        // 項目9: switch-case ラベル
        switchLabel: `case_${b.estimatedOpcode !== undefined ? b.estimatedOpcode : i}`,
      });
    }
  }
  // opcode 番号でソート（直線命令列の確定）
  flat.sort((a, b) => a.opcode - b.opcode);
  return flat;
}

// ════════════════════════════════════════════════════════════════════════
//  項目8: executeTrace — vmhook ログから register push/pop を再現
//
//  入力: vmTraceEntries (logParser 由来), opcodeMap (動的再構築済み)
//  出力: レジスタ状態履歴 + 疑似実行ログ
// ════════════════════════════════════════════════════════════════════════
function executeTrace(vmTraceEntries, opcodeMap, constPool) {
  if (!vmTraceEntries || vmTraceEntries.length === 0)
    return { success: false, error: 'traceが空', regHistory: [], pseudoLog: [] };

  const regs    = {};   // レジスタファイル: reg番号 → 値
  const stack   = [];   // 疑似スタック
  const pseudoLog = [];
  const regHistory = [];

  // opcode解決: 動的マップ優先
  const resolve = (op) => {
    const k = String(op);
    if (opcodeMap && opcodeMap[k]) return opcodeMap[k].replace('_inferred','').replace('_heuristic','');
    if (LUA51_OPCODES[k]) return LUA51_OPCODES[k];
    return `OP_${op}`;
  };

  // 定数解決ヘルパー
  const resolveConst = (idx) => {
    if (!constPool) return `K[${idx}]`;
    // RK(idx): idx >= 256 は定数参照
    const realIdx = idx >= 256 ? idx - 256 : idx;
    const elem = constPool[realIdx] || constPool[realIdx - 1];
    if (!elem) return `K[${idx}]`;
    if (elem.type === 'string') return `"${elem.value.substring(0, 40)}"`;
    if (elem.type === 'number') return String(elem.value);
    return String(elem.value);
  };

  // 項目14: max iteration 制限（無限ループ防止）
  const maxIter = Math.min(vmTraceEntries.length, MAX_DISPATCH_ITERATIONS);

  for (let i = 0; i < maxIter; i++) {
    const e      = vmTraceEntries[i];
    const op     = e.l !== undefined ? e.l : e.op;
    const A      = e.A !== undefined ? e.A : e.arg1;
    const B      = e.B !== undefined ? e.B : e.arg2;
    const C      = e.C !== undefined ? e.C : e.arg3;
    const pc     = e.pc !== undefined ? e.pc : (e.ip || i);
    const opName = resolve(op);

    let logLine = `[${pc}] ${opName}`;

    switch (opName) {
      case 'MOVE':
        regs[A] = regs[B] !== undefined ? regs[B] : `v${B}`;
        logLine += ` v${A} = v${B}  -- ${JSON.stringify(regs[A]).substring(0,40)}`;
        break;
      case 'LOADK':
        regs[A] = resolveConst(B);
        logLine += ` v${A} = ${regs[A]}`;
        break;
      case 'LOADBOOL':
        regs[A] = B ? true : false;
        logLine += ` v${A} = ${regs[A]}`;
        break;
      case 'LOADNIL':
        for (let r = A; r <= B; r++) regs[r] = null;
        logLine += ` v${A}..v${B} = nil`;
        break;
      case 'GETGLOBAL':
        regs[A] = `_G[${resolveConst(B)}]`;
        logLine += ` v${A} = _G[${resolveConst(B)}]`;
        break;
      case 'SETGLOBAL':
        logLine += ` _G[${resolveConst(B)}] = v${A} (${JSON.stringify(regs[A]).substring(0,30)})`;
        break;
      case 'GETTABLE':
        regs[A] = `${regs[B] || `v${B}`}[${resolveConst(C)}]`;
        logLine += ` v${A} = ${regs[A]}`;
        break;
      case 'SETTABLE':
        logLine += ` v${A}[${resolveConst(B)}] = ${regs[C] || `v${C}`}`;
        break;
      case 'NEWTABLE':
        regs[A] = {};
        logLine += ` v${A} = {}`;
        break;
      case 'ADD':  regs[A] = `(${resolveConst(B)}) + (${resolveConst(C)})`; logLine += ` v${A} = ${regs[A]}`; break;
      case 'SUB':  regs[A] = `(${resolveConst(B)}) - (${resolveConst(C)})`; logLine += ` v${A} = ${regs[A]}`; break;
      case 'MUL':  regs[A] = `(${resolveConst(B)}) * (${resolveConst(C)})`; logLine += ` v${A} = ${regs[A]}`; break;
      case 'DIV':  regs[A] = `(${resolveConst(B)}) / (${resolveConst(C)})`; logLine += ` v${A} = ${regs[A]}`; break;
      case 'CALL':
        stack.push({ fn: regs[A] || `v${A}`, args: A, nargs: (B||1)-1, nret: (C||1)-1, pc });
        logLine += ` ${regs[A] || `v${A}`}(${Array.from({length:(B||1)-1}, (_,j) => regs[A+1+j] || `v${A+1+j}`).join(', ')})`;
        break;
      case 'RETURN':
        logLine += ` return ${A ? Array.from({length:Math.max(1,(B||1)-1)}, (_,j) => regs[(A||0)+j] || `v${(A||0)+j}`).join(', ') : ''}`;
        break;
      case 'JMP':
        logLine += ` goto ${pc + 1 + (B||0)}`;
        break;
      default:
        logLine += ` A=${A} B=${B} C=${C}`;
    }

    pseudoLog.push(logLine);
    regHistory.push({ pc, op: opName, snapshot: { ...regs } });
  }

  const truncated = vmTraceEntries.length > maxIter;
  return {
    success:   true,
    pseudoLog,
    regHistory: regHistory.slice(0, 500),   // 最大500エントリ
    finalRegs:  regs,
    callStack:  stack,
    truncated,
    processedCount: maxIter,
    method: 'execute_trace',
  };
}

// ════════════════════════════════════════════════════════════════════════
//  項目9: convertToSwitchCase — if l < N then チェーンを switch-case 構造へ
// ════════════════════════════════════════════════════════════════════════
function convertToSwitchCase(flatInstructions, jVar) {
  if (!flatInstructions || flatInstructions.length < 4) return null;

  const lines = [];
  lines.push(`-- ══ switch-case 変換済み VM ディスパッチ ══`);
  lines.push(`-- 元の if ${jVar || 'l'} < N then チェーン → case 構造`);
  lines.push('');
  lines.push(`local function __dispatch(${jVar || 'l'})`);
  lines.push(`  -- opcode ${flatInstructions[0].opcode} 〜 ${flatInstructions[flatInstructions.length-1].opcode}`);

  for (const instr of flatInstructions) {
    lines.push(`  -- ${instr.switchLabel || `case_${instr.opcode}`}: opcode=${instr.opcode} threshold=${instr.threshold}`);
    // ボディを整形して出力
    const bodyLines = (instr.body || '').split('\n')
      .map(l => '    ' + l.trim())
      .filter(l => l.trim().length > 0)
      .slice(0, 20);
    lines.push(`  if ${jVar || 'l'} == ${instr.opcode} then`);
    lines.push(...bodyLines);
    lines.push(`  end`);
  }

  lines.push(`end`);
  return lines.join('\n');
}

// ════════════════════════════════════════════════════════════════════════
//  項目13: simplifyStateMachine — 最終出力前に実行する後処理
//
//  1. 連続する同一 opcode を圧縮
//  2. 未解決 OP_xxx をコメントに変換
//  3. 空ブロックを削除
//  4. インデント正規化
// ════════════════════════════════════════════════════════════════════════
function simplifyStateMachine(code) {
  if (!code) return code;
  let result = code;

  // 1. 連続する同一命令コメントを圧縮
  result = result.replace(/(-- \[(\d+)\] (OP_\w+)\([^)]*\)\n){3,}/g,
    (m) => {
      const count = m.split('\n').filter(Boolean).length;
      const first = m.match(/-- \[(\d+)\]/)?.[1] || '?';
      return `-- [${first}...] OP_UNKNOWN ×${count}回\n`;
    });

  // 2. 未解決 opcode（OP_UNKNOWN / OP_数字）をコメントに変換
  result = result.replace(/^(\s*)-- \[\d+\] OP_UNKNOWN\([^)]*\)$/gm,
    (m) => m.replace(/^(\s*)--/, '$1-- [未解決]'));

  // 3. 空の if ブロックを削除
  result = result.replace(/if\s+[^\n]+\n\s*end\s*--[^\n]*/g, '');

  // 4. ::lbl_N:: が直後の goto lbl_N と対になる場合は削除（自己ループ）
  result = result.replace(/::lbl_(\d+)::\s*\ngoto lbl_\1\b[^\n]*/g, '-- [自己ループ除去]');

  // 5. 3行以上連続する空行を1行に
  result = result.replace(/\n{4,}/g, '\n\n');

  // 6. 末尾空白削除
  result = result.replace(/[ \t]+$/gm, '');

  return result.trim();
}

// ════════════════════════════════════════════════════════════════════════
//  vmDecompiler — メイン VM デコンパイラ
//
//  項目6: VM検出後は luaPrinter を呼ばず必ず decompiler.js 内で処理
//  項目15: vmhook ログがあれば実行順優先、なければ静的解析へフォールバック
// ════════════════════════════════════════════════════════════════════════
function vmDecompiler(vmTrace, bytecodeDump, opcodeMap) {
  if (!vmTrace || vmTrace.length === 0)
    return { success: false, error: 'vmTraceが空', pseudoCode: '', method: 'vm_decompile' };

  // 項目15: vmhook ログが存在するか確認
  const hasVmhookLog = vmTrace.length > 0;

  // 項目5+15: opcodeMap を動的再構築（staticFallback は opcodeMap.map を使用）
  const { dynamicOpcodeResolver: dynResolver } = require('./interpreterParser');
  const bInstructions = bytecodeDump ? Object.values(bytecodeDump).flat() : [];
  const dynamicResult = hasVmhookLog
    ? buildOpcodeMapFromTrace(vmTrace, bInstructions)
    : { opcodeMap: (opcodeMap && opcodeMap.map) || {}, source: 'static_fallback', confidence: 20 };

  const resolvedOpcodeMap = dynamicResult.opcodeMap;

  // 定数テーブル
  const constTables = {};
  for (const [tname, nums] of Object.entries(bytecodeDump || {})) {
    constTables[tname] = nums;
  }

  // IR 変換
  const ir = [];
  for (const entry of vmTrace) {
    const { ip, op, arg1, arg2, arg3 } = entry;
    const opKey  = String(op !== null && op !== undefined ? op : 'UNKNOWN');
    const opName = resolvedOpcodeMap[opKey] || LUA51_OPCODES[opKey] || `OP_${op}`;
    ir.push({ ip, opName, op, arg1, arg2, arg3 });
  }

  // CFG 構築
  const firstIp = ir.length > 0 ? ir[0].ip : 0;
  const leaders   = new Set([firstIp]);
  const jumpTargets = new Set();
  for (const inst of ir) {
    const cat = _getCat(inst.opName);
    if (['JUMP','EQ','LT','LE','TEST','TESTSET'].includes(cat)) {
      if (inst.opName === 'JMP' && inst.arg2 !== null) {
        const target = inst.ip + 1 + inst.arg2;
        leaders.add(target);
        jumpTargets.add(target);
      }
      leaders.add(inst.ip + 1);
    }
    if (cat === 'LOOP') {
      leaders.add(inst.ip);
      if (inst.arg2 !== null) leaders.add(inst.ip + 1 + inst.arg2);
    }
  }

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

  // 疑似 Lua 生成
  const lines = [];
  lines.push('-- ══ YAJU VM Decompiled (疑似Lua) ══');
  lines.push(`-- opcodeMap source: ${dynamicResult.source} (confidence: ${dynamicResult.confidence}%)`);
  if (Object.keys(constTables).length > 0) {
    for (const [tname, nums] of Object.entries(constTables)) {
      lines.push(`local ${tname}_const = {${nums.slice(0,16).join(',')}${nums.length > 16 ? ',...' : ''}}`);
    }
    lines.push('');
  }

  const regName = (n) => n !== null && n !== undefined ? `v${n}` : '_';
  let indentLevel = 0;
  const indent = () => '  '.repeat(indentLevel);

  for (const block of blocks) {
    if (block.isLoopTarget)
      lines.push(`${indent()}::lbl_${block.startIp}::`);

    for (const inst of block.instructions) {
      const { ip, opName, arg1: A, arg2: B, arg3: C } = inst;
      const line = vmDecompileInstruction(opName, ip, A, B, C, resolvedOpcodeMap);
      lines.push(`${indent()}${line}`);
    }
  }

  lines.push('-- ══ End of Decompilation ══');

  // 項目13: 最終出力前に simplifyStateMachine() を必ず実行
  const rawCode   = lines.join('\n');
  const pseudoCode = simplifyStateMachine(rawCode);

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
    opcodeMapSource:     dynamicResult.source,
    opcodeMapConfidence: dynamicResult.confidence,
    method: 'vm_decompile',
  };
}

function _getCat(opName) {
  const clean = (opName || '').replace('_inferred','').replace('_heuristic','');
  const CATS = {
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
  return CATS[clean] || 'UNKNOWN';
}

function reconstructedLuaBuilder(vmTrace, bytecodeDump, opcodeMap) {
  return vmDecompiler(vmTrace, bytecodeDump, opcodeMap);
}

// ════════════════════════════════════════════════════════════════════════
//  weredevAnalyze — Weredev VM 専用解析エンジン
//  項目6: VM検出後は luaPrinter を経由せず直接 decompiler.js 内で完結
//  項目15: vmhookログがあればopcode実行順優先
// ════════════════════════════════════════════════════════════════════════
function weredevAnalyze(code, vmTraceEntries, bTableLog, strLogEntries, options) {
  const MAX_INSTRUCTIONS = (options && options.maxInstructions) || MAX_DISPATCH_ITERATIONS;
  const result = {
    isWeredev:      false,
    dispatchLoop:   null,
    tableNames:     [],
    tables:         {},
    escapedStrings: null,
    stringBuilder:  null,
    opcodeMap:      {},
    remapped:       {},
    decompiled:     [],
    stringsFound:   [],
    method:         'weredev_analyze',
  };

  result.isWeredev = isWeredevObfuscated(code);

  // 項目3: detectVmDispatchLoop は AST 変換せず dispatcher 展開済み結果を返す
  result.dispatchLoop = detectVmDispatchLoop(code);
  result.tableNames   = extractVmTableNames(code);

  for (const name of result.tableNames.slice(0, 20)) {
    const tbl = extractVmTable(code, name);
    if (tbl && tbl.count >= 8) result.tables[name] = tbl;
  }

  // 項目15: vmhookログが存在する場合は実行順優先
  const hasTrace = vmTraceEntries && vmTraceEntries.length > 0;
  const bInstructions = bTableLog && bTableLog.found ? bTableLog.instructions : [];

  const mapResult = hasTrace
    ? buildOpcodeMapFromTrace(vmTraceEntries, bInstructions)
    : { opcodeMap: {}, source: 'static_fallback', confidence: 0 };

  result.opcodeMap      = mapResult.opcodeMap;
  result.opcodeSource   = mapResult.source;
  result.opcodeConfidence = mapResult.confidence;

  const remapResult = remapOpcodes(vmTraceEntries || [], result.opcodeMap);
  result.remapped        = remapResult.remapped;
  result.remapConfidence = remapResult.confidence;

  // 項目8: executeTrace でレジスタ状態を再現
  if (hasTrace) {
    const constPool = Object.values(result.tables).length > 0
      ? Object.values(result.tables)[0].elements
      : null;
    result.traceExecution = executeTrace(vmTraceEntries, result.remapped, constPool);
  }

  // 項目6: 疑似コード生成は luaPrinter を使わず直接生成
  const traceToDecompile = (vmTraceEntries || []).slice(0, MAX_INSTRUCTIONS);
  const decompLines = [];
  decompLines.push(`-- ══ Weredev VM Decompiled (maxInstructions=${MAX_INSTRUCTIONS}) ══`);
  decompLines.push(`-- opcodeMap: ${mapResult.source} (confidence: ${mapResult.confidence}%)`);

  let prevPc = -1;
  for (const e of traceToDecompile) {
    const pc     = e.pc !== undefined ? e.pc : (e.ip || 0);
    const opcode = e.l  !== undefined ? e.l  : e.op;
    const A      = e.A  !== undefined ? e.A  : e.arg1;
    const B      = e.B  !== undefined ? e.B  : e.arg2;
    const C      = e.C  !== undefined ? e.C  : e.arg3;

    if (prevPc !== -1 && pc !== prevPc + 1) decompLines.push(`::lbl_${pc}::`);

    const lua = vmDecompileInstruction(opcode, pc, A, B, C, result.remapped);
    decompLines.push(`  -- [${pc}] ${String(opcode).padStart(3)} | ${lua}`);
    prevPc = pc;
  }

  if (traceToDecompile.length >= MAX_INSTRUCTIONS)
    decompLines.push(`-- [WARNING] maxInstructions=${MAX_INSTRUCTIONS} に達したため打ち切り`);
  decompLines.push('-- ══ End ══');

  // 項目13: 最終出力前に simplifyStateMachine() を必ず実行
  const rawDecompiled = decompLines.join('\n');
  result.decompiledCode = simplifyStateMachine(rawDecompiled);
  result.decompiled     = result.decompiledCode.split('\n');

  if (strLogEntries && strLogEntries.length > 0) {
    result.stringsFound = strLogEntries
      .filter(e => e.val && e.val.length > 0)
      .slice(0, 200)
      .map(e => ({ idx: e.idx, val: e.val }));
  }

  return result;
}

// ════════════════════════════════════════════════════════════════════════
//  weredevFullDecompile — フル解析パイプライン
// ════════════════════════════════════════════════════════════════════════
function weredevFullDecompile(code) {
  const result = {
    success:false, method:'weredev_full_decompile',
    context:{}, constPools:{}, accessors:{}, dispatchLoops:[],
    opcodeBlocks:[], resolvedCode:'', pseudoLua:'', error:null, stats:{},
  };
  if (!code || code.length === 0) { result.error = 'コードが空です'; return result; }

  // 項目10: return(function(...)) ラッパーを先に除去
  const unwrapped = unwrapVmWrapper(code);
  const workCode  = unwrapped.unwrapped ? unwrapped.code : code;
  result.stats.wrapperUnwrapped = unwrapped.unwrapped;

  // フェーズ1: コンテキスト変数名検出
  const ctx = detectWeredevContext(workCode);
  result.context = ctx;

  // フェーズ2: 定数プール抽出
  const constPools = extractWeredevConstPool(workCode);
  result.constPools = constPools;
  result.stats.constPoolCount  = Object.keys(constPools).length;
  result.stats.totalConstants  = Object.values(constPools).reduce((s,p)=>s+p.count,0);

  // フェーズ3: Z() アクセサ解析
  const accessors = extractWeredevZAccessor(workCode, constPools);
  result.accessors = accessors;
  result.stats.accessorCount = Object.keys(accessors).length;
  if (Object.keys(accessors).length > 0) {
    const fa = Object.values(accessors)[0];
    ctx.poolVar = fa.poolName;
    ctx.zFunc   = fa.funcName;
  }

  // フェーズ4: ディスパッチループ抽出 (項目3: dispatcher 展開済み)
  const loops = extractWeredevDispatchLoop(workCode);
  result.dispatchLoops = loops;
  result.stats.dispatchLoopCount = loops.length;
  result.stats.totalOpcodeBlocks = loops.reduce((s,l)=>s+l.blockCount,0);

  // フェーズ4b: 項目7: dispatcherFlatten で直線命令列へ変換
  const flatInstructions = dispatcherFlatten(loops);
  result.stats.flatInstructionCount = flatInstructions.length;

  // フェーズ5: Z(N) → 定数解決
  const resolved = resolveWeredevZCalls(workCode, accessors, constPools);
  result.resolvedCode = resolved.code;
  result.stats.resolvedZCalls = resolved.resolved;

  // フェーズ5b: 項目12: Base64風デコードループを削除
  const cleanResult = removeConstDecodeLoop(result.resolvedCode);
  result.resolvedCode = cleanResult.code;
  result.stats.removedDecodeLoops = cleanResult.removed;

  // フェーズ6: opcodeブロック解析
  const allBlocks = [];
  const flatPool  = _buildFlatConstPool(constPools, accessors);

  for (const loop of loops) {
    const numbered = assignWeredevOpcodes(loop.dispatchBlocks);
    for (const block of numbered) {
      const ops      = analyzeWeredevOpcodeBlock(block, ctx);
      const operands = extractWeredevOperands(block.body, ctx);
      const { A, B, C } = operands;
      const detectedOpName = _inferOpNameFromOperands(operands, block.body, ctx);
      const opNum          = block.estimatedOpcode;
      const instrLua       = vmDecompileInstruction(detectedOpName, opNum, A, B, C, LUA51_OPCODES);
      const instrResolved  = resolveInstrConstants(instrLua, flatPool);

      allBlocks.push({
        threshold:       block.threshold,
        estimatedOpcode: opNum,
        opName:          detectedOpName,
        A, B, C,
        instrLua:        instrResolved,
        ops,
        rawBody:         (block.body || '').substring(0, 300),
      });
    }
  }
  result.opcodeBlocks = allBlocks;
  result.stats.opcodeBlocksDecompiled = allBlocks.length;

  // フェーズ7: 疑似 Lua コード生成
  // 項目9: if チェーンが多い場合は switch-case 構造へ変換
  let pseudoLua;
  if (flatInstructions.length >= 4 && flatInstructions.some(f => f.switchLabel)) {
    const switchCode = convertToSwitchCase(flatInstructions, ctx.loopVar || 'l');
    pseudoLua = switchCode
      ? buildWeredevPseudoLua(result, ctx, workCode) + '\n\n' + switchCode
      : buildWeredevPseudoLua(result, ctx, workCode);
  } else {
    pseudoLua = buildWeredevPseudoLua(result, ctx, workCode);
  }

  // 項目13: 最終出力前に必ず simplifyStateMachine() を実行
  result.pseudoLua = simplifyStateMachine(pseudoLua);
  result.success   = result.pseudoLua.length > 50 ||
    result.stats.totalConstants > 0 || result.stats.resolvedZCalls > 0;

  return result;
}

// ────────────────────────────────────────────────────────────────────────
//  cleanWeredevOutputCode
// ────────────────────────────────────────────────────────────────────────
function cleanWeredevOutputCode(code, ctx) {
  if (!code) return '';
  let r = code;
  r = r.replace(/local\s+[A-Za-z_]\w*\s*=\s*\{[^}]{500,}\}/gs, '-- [定数プール省略]');
  r = r.replace(/local\s+[A-Za-z_]\w*\s*=\s*function\s*\([^)]+\)\s*return\s+[A-Za-z_]\w*\s*\[[^\]]+\]\s*end\s*/g, '');
  r = r.replace(/\n{4,}/g, '\n\n');
  r = r.replace(/[ \t]+$/gm, '');
  return r.trim();
}

// ────────────────────────────────────────────────────────────────────────
//  buildWeredevPseudoLua
// ────────────────────────────────────────────────────────────────────────
function buildWeredevPseudoLua(analysis, ctx, originalCode) {
  const lines = [];
  lines.push('-- ════════════════════════════════════════════════════════');
  lines.push('-- Weredev VM 逆コンパイル結果 (YAJU Deobfuscator v3)');
  lines.push('-- ════════════════════════════════════════════════════════');
  lines.push('');

  for (const [name, pool] of Object.entries(analysis.constPools)) {
    if (pool.count === 0) continue;
    const strings = pool.elements.filter(e => e && e.type === 'string' && e.value.length > 0).slice(0, 30);
    if (strings.length > 0) {
      lines.push(`-- ── 定数プール: ${name} (${pool.count}要素) ─────`);
      lines.push(`--   文字列: ${strings.map(s=>`"${s.value.substring(0,40).replace(/\n/g,'\\n')}"`).join(', ')}`);
    }
    const nums = pool.elements.filter(e => e && e.type === 'number').slice(0, 20);
    if (nums.length > 0) lines.push(`--   数値: ${nums.map(n=>String(n.value)).join(', ')}`);
  }
  if (Object.keys(analysis.constPools).length > 0) lines.push('');

  for (const [name, acc] of Object.entries(analysis.accessors)) {
    lines.push(`-- アクセサ: ${name}(i) = ${acc.poolName}[i - ${acc.offset}]`);
  }
  if (Object.keys(analysis.accessors).length > 0) lines.push('');

  if (analysis.stats.resolvedZCalls > 0) {
    lines.push(`-- Z()解決: ${analysis.stats.resolvedZCalls}件の定数参照を展開済み`);
    lines.push('');
  }

  if (analysis.stats.removedDecodeLoops > 0) {
    lines.push(`-- 項目12: ${analysis.stats.removedDecodeLoops}件のデコードループを削除`);
    lines.push('');
  }

  if (analysis.stats.wrapperUnwrapped) {
    lines.push('-- 項目10: return(function(...)) ラッパーを除去済み');
    lines.push('');
  }

  for (const loop of analysis.dispatchLoops) {
    lines.push(`-- VMディスパッチ: while ${loop.loopVar} do  [${loop.blockCount}ブロック]`);
  }
  if (analysis.dispatchLoops.length > 0) lines.push('');

  if (analysis.opcodeBlocks.length > 0) {
    lines.push('-- ── opcodeブロック逆コンパイル ─────────────────────────────');
    lines.push('');
    for (const block of analysis.opcodeBlocks) {
      const opName  = block.opName || `OP_${block.estimatedOpcode}`;
      const abcInfo = [
        block.A !== null && block.A !== undefined ? `A=${block.A}` : null,
        block.B !== null && block.B !== undefined ? `B=${block.B}` : null,
        block.C !== null && block.C !== undefined ? `C=${block.C}` : null,
      ].filter(Boolean).join(' ');
      lines.push(`-- [opcode ${String(block.estimatedOpcode).padStart(2,' ')}] ${opName.padEnd(12,' ')} ${abcInfo}`);
      if (block.instrLua && !/^-- OP_|^-- UNKNOWN/.test(block.instrLua)) {
        lines.push(`  ${block.instrLua}`);
      } else {
        for (const op of block.ops) {
          if (op.kind === 'PC_INCR' || op.kind === 'RAW') continue;
          lines.push(`  ${op.lua}`);
        }
      }
    }
    lines.push('');
  }

  const resolvedCode = analysis.resolvedCode || originalCode;
  const cleanedCode  = cleanWeredevOutputCode(resolvedCode, ctx);
  if (cleanedCode.length > 50) {
    lines.push('-- ── Z()解決後・クリーンアップ済みコード ──────────────────────');
    lines.push(cleanedCode);
  }

  return lines.join('\n');
}

// ────────────────────────────────────────────────────────────────────────
//  weredevFullDecompileHandler — API エントリポイント
// ────────────────────────────────────────────────────────────────────────
function weredevFullDecompileHandler(code) {
  try {
    const r = weredevFullDecompile(code);
    const poolSummary = Object.fromEntries(
      Object.entries(r.constPools).map(([k,v]) => [k, {
        count:            v.count,
        isLikelyConstPool: v.isLikelyConstPool,
        strings: v.elements.filter(e=>e&&e.type==='string').slice(0,20).map(e=>e.value.substring(0,60)),
        numbers: v.elements.filter(e=>e&&e.type==='number').slice(0,20).map(e=>e.value),
      }])
    );
    if (!r.success) {
      return {
        success:false, method:'weredev_full_decompile',
        error: r.error || 'Weredev VMパターンが検出できませんでした',
        context:r.context, stats:r.stats, constPools:poolSummary,
      };
    }
    return {
      success:true, method:'weredev_full_decompile',
      result: r.pseudoLua,
      resolvedCode: r.resolvedCode.length < 500000
        ? r.resolvedCode : r.resolvedCode.substring(0,500000)+'...[truncated]',
      context:r.context, stats:r.stats, constPools:poolSummary,
      accessors:r.accessors,
      dispatchLoops: r.dispatchLoops.map(l=>({
        loopVar:l.loopVar, blockCount:l.blockCount, isWhileTrue:l.isWhileTrue||false,
      })),
      opcodeBlocks: r.opcodeBlocks.map(b=>({
        threshold:b.threshold, estimatedOpcode:b.estimatedOpcode,
        opName: b.opName || `OP_${b.estimatedOpcode}`,
        ops: b.ops.map(o=>o.lua),
      })),
    };
  } catch(e) {
    return { success:false, method:'weredev_full_decompile', error:'エラー: '+e.message };
  }
}

module.exports = {
  vmDecompiler, reconstructedLuaBuilder,
  weredevAnalyze, cleanWeredevOutputCode, buildWeredevPseudoLua,
  weredevFullDecompile, weredevFullDecompileHandler,
  // 追加エクスポート
  dispatcherFlatten,       // 項目7
  executeTrace,            // 項目8
  convertToSwitchCase,     // 項目9
  simplifyStateMachine,    // 項目13
};
