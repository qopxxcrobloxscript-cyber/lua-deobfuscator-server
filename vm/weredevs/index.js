// vm/weredevs/index.js
'use strict';

// ════════════════════════════════════════════════════════════════════════
//  Weredevs VM 解析パイプライン
//
//  実行順序:
//    1. extractor        — bytecode テーブル・定数プール・アクセサ・dispatch ループ抽出
//    2. interpreterParser — VM コンテキスト検出・dispatch ブロック解析
//    3. opcodeMap        — opcode 番号付け・オペランド推定
//    4. emulator.run()   — 命令をステップ実行して execution trace 生成
//    5. decompiler       — trace → 疑似 Lua コード生成
//
//  VM table 名の検出は固定名ではなく regex ベース:
//    /local\s+(\w+)\s*=\s*{/
//  により難読化ごとに変わる名前に対応する。
// ════════════════════════════════════════════════════════════════════════

// ── モジュール読み込み ──────────────────────────────────────────────────
const {
  extractVmTableNames, extractVmTable,
  extractWeredevConstPool, extractWeredevZAccessor,
  extractWeredevDispatchLoop, _wdEscapeRegex,
  extractIfJBlocks, _flattenIfJTree, _collectLeafStatements,
  _splitIfThenElse, _findIfBlockEnd,
  dumpBytecodeTables, vmBytecodeExtractor,
  parseConstPoolBody, resolveConstPoolElement, detectIfConstPool,
} = require('./extractor');

const {
  detectVmDispatchLoop, detectWeredevContext,
  analyzeWeredevOpcodeBlock, extractWeredevOperands,
  _buildFlatConstPool, resolveWeredevZCalls,
} = require('./interpreterParser');

const {
  LUA51_OPCODES, OPCODE_CATEGORIES,
  vmTraceAnalyzer, buildOpcodeMapFromTrace, remapOpcodes,
  vmDecompileInstruction, assignWeredevOpcodes,
  _inferOpNameFromOperands, resolveInstrConstants,
} = require('./opcodeMap');

const {
  WeredevVM, emulateWeredevVM,
  buildConstantsFromPools, buildBytecodeFromBlocks, traceToVmTrace,
} = require('./emulator');

const {
  vmDecompiler, reconstructedLuaBuilder,
  weredevAnalyze, cleanWeredevOutputCode, buildWeredevPseudoLua,
  weredevFullDecompile, weredevFullDecompileHandler,
} = require('./decompiler');

// ════════════════════════════════════════════════════════════════════════
//  weredevPipeline — メイン5段パイプライン
//
//  @param {string} code      — 難読化済み Lua ソースコード
//  @param {object} [options]
//    maxSteps    {number}  — エミュレータ最大ステップ数 (default: 200000)
//    maxTrace    {number}  — trace 最大保持件数         (default: 50000)
//    skipEmulate {boolean} — emulate をスキップして静的解析のみ返す
// ════════════════════════════════════════════════════════════════════════
function weredevPipeline(code, options) {
  const opts        = options || {};
  const skipEmulate = opts.skipEmulate || false;

  const result = {
    success: false, method: 'weredev_pipeline',
    stages: {}, pseudoLua: '', resolvedCode: '', error: null,
  };

  if (!code || code.length === 0) {
    result.error = 'コードが空です';
    return result;
  }

  // ────────────────────────────────────────────────────────────────────
  //  Stage 1: extractor
  //  /local\s+(\w+)\s*=\s*{/ で VM table 名を動的検出（固定名廃止）し、
  //  定数プール・アクセサ・dispatch ループを抽出する。
  // ────────────────────────────────────────────────────────────────────
  const tableNames    = extractVmTableNames(code);        // regex ベース
  const constPools    = extractWeredevConstPool(code);
  const accessors     = extractWeredevZAccessor(code, constPools);
  const dispatchLoops = extractWeredevDispatchLoop(code);

  result.stages.extractor = {
    tableNames,
    constPoolCount:    Object.keys(constPools).length,
    accessorCount:     Object.keys(accessors).length,
    dispatchLoopCount: dispatchLoops.length,
  };

  // ────────────────────────────────────────────────────────────────────
  //  Stage 2: interpreterParser
  //  VM コンテキスト変数名を特定し、dispatch ブロックを解析する。
  // ────────────────────────────────────────────────────────────────────
  const ctx = detectWeredevContext(code);
  const accList = Object.values(accessors);
  if (accList.length > 0) { ctx.poolVar = accList[0].poolName; ctx.zFunc = accList[0].funcName; }

  const bestLoop = dispatchLoops.length > 0
    ? dispatchLoops.reduce((a, b) => b.blockCount > a.blockCount ? b : a)
    : null;

  const analyzedBlocks = bestLoop
    ? bestLoop.dispatchBlocks.map(block => ({ ...block, _ops: analyzeWeredevOpcodeBlock(block, ctx) }))
    : [];

  result.stages.interpreterParser = {
    ctx, loopVar: ctx.loopVar, analyzedBlockCount: analyzedBlocks.length,
  };

  // ────────────────────────────────────────────────────────────────────
  //  Stage 3: opcodeMap
  //  dispatch ブロックに opcode 番号を付与し A/B/C オペランドを推定する。
  // ────────────────────────────────────────────────────────────────────
  const numberedBlocks = analyzedBlocks.length > 0
    ? assignWeredevOpcodes(analyzedBlocks) : [];

  const enrichedBlocks = numberedBlocks.map(block => {
    const operands   = extractWeredevOperands(block.body || '', ctx);
    const detectedOp = _inferOpNameFromOperands(operands, block.body || '', ctx);
    return { ...block, opName: detectedOp, A: operands.A, B: operands.B, C: operands.C };
  });

  result.stages.opcodeMap = {
    numberedBlockCount: numberedBlocks.length,
    opNames: enrichedBlocks.slice(0, 20).map(b => b.opName),
  };

  // ────────────────────────────────────────────────────────────────────
  //  Stage 4: emulator.run()
  //  enrichedBlocks + constPools から WeredevVM を実行し execution trace を生成。
  //  skipEmulate が true の場合はスキップ。
  // ────────────────────────────────────────────────────────────────────
  let vmTrace = [], emulResult = null;

  if (!skipEmulate && enrichedBlocks.length > 0) {
    emulResult = emulateWeredevVM({
      constPools, accessors, dispatchLoops, ctx,
      numberedBlocks: enrichedBlocks,
      options: { maxSteps: opts.maxSteps || 200_000, maxTrace: opts.maxTrace || 50_000 },
    });
    vmTrace = emulResult.vmTrace || [];
  }

  result.stages.emulator = emulResult ? {
    success: emulResult.success, steps: emulResult.steps,
    traceLen: vmTrace.length,    haltReason: emulResult.haltReason,
    callCount: (emulResult.callLog || []).length,
    jumpCount: (emulResult.jumpLog || []).length,
    error: emulResult.error || null,
  } : { skipped: true };

  // ────────────────────────────────────────────────────────────────────
  //  Stage 5: decompiler
  //  vmTrace があれば vmDecompiler（動的）、なければ weredevFullDecompileHandler（静的）。
  // ────────────────────────────────────────────────────────────────────
  let decompResult;

  if (vmTrace.length > 0) {
    const bDump      = _buildBytecodeDump(tableNames, code);
    const opcodeMapR = buildOpcodeMapFromTrace(vmTrace, []);
    decompResult     = vmDecompiler(vmTrace, bDump, opcodeMapR.opcodeMap);
    decompResult._via = 'emulator_trace';
  } else {
    decompResult      = weredevFullDecompileHandler(code);
    decompResult._via = 'static_fallback';
  }

  result.stages.decompiler = {
    success: decompResult.success, via: decompResult._via, method: decompResult.method,
  };
  result.success      = decompResult.success;
  result.pseudoLua    = decompResult.pseudoCode || decompResult.result || '';
  result.resolvedCode = decompResult.resolvedCode || '';
  result.decompResult = decompResult;

  return result;
}

// ── 内部ヘルパー ─────────────────────────────────────────────────────────
function _buildBytecodeDump(tableNames, code) {
  const dump = {};
  for (const name of tableNames.slice(0, 10)) {
    const tbl = extractVmTable(code, name);
    if (tbl && tbl.nums && tbl.nums.length > 0) dump[name] = tbl.nums;
  }
  return dump;
}

// ════════════════════════════════════════════════════════════════════════
//  exports — 全サブモジュールのシンボル + パイプライン関数
// ════════════════════════════════════════════════════════════════════════
module.exports = {
  // パイプライン (新規)
  weredevPipeline,
  // extractor
  extractVmTableNames, extractVmTable,
  extractWeredevConstPool, extractWeredevZAccessor, extractWeredevDispatchLoop,
  _wdEscapeRegex, extractIfJBlocks, _flattenIfJTree, _collectLeafStatements,
  _splitIfThenElse, _findIfBlockEnd, dumpBytecodeTables, vmBytecodeExtractor,
  parseConstPoolBody, resolveConstPoolElement, detectIfConstPool,
  // interpreterParser
  detectVmDispatchLoop, detectWeredevContext, analyzeWeredevOpcodeBlock,
  extractWeredevOperands, _buildFlatConstPool, resolveWeredevZCalls,
  // opcodeMap
  LUA51_OPCODES, OPCODE_CATEGORIES, vmTraceAnalyzer, buildOpcodeMapFromTrace,
  remapOpcodes, vmDecompileInstruction, assignWeredevOpcodes,
  _inferOpNameFromOperands, resolveInstrConstants,
  // emulator
  WeredevVM, emulateWeredevVM, buildConstantsFromPools,
  buildBytecodeFromBlocks, traceToVmTrace,
  // decompiler
  vmDecompiler, reconstructedLuaBuilder, weredevAnalyze,
  cleanWeredevOutputCode, buildWeredevPseudoLua,
  weredevFullDecompile, weredevFullDecompileHandler,
};
