// vm/weredevs/index.js
'use strict';

// ────────────────────────────────────────────────────────────────────────
//  weredevs/index.js — 名前空間まとめ + 項目6の実装
//
//  項目6: VM検出後は luaPrinter を呼ばず必ず decompiler.js に渡す
//         → isWeredevObfuscated/vmDetector で検出後の全ルートを
//           decompiler.js の関数に直結させる
// ────────────────────────────────────────────────────────────────────────

// ── opcodeMap ────────────────────────────────────────────────────────────
const {
  LUA51_OPCODES, OPCODE_CATEGORIES,
  vmTraceAnalyzer, buildOpcodeMapFromTrace, remapOpcodes,
  vmDecompileInstruction, assignWeredevOpcodes,
  _inferOpNameFromOperands, resolveInstrConstants,
} = require('./opcodeMap');

// ── extractor ────────────────────────────────────────────────────────────
const {
  extractFirstLocalName,
  extractVmTableNames, extractVmTable,
  extractWeredevConstPool,
  extractWeredevZAccessor, _wdEscapeRegex,
  extractWeredevDispatchLoop,
  dumpBytecodeTables, vmBytecodeExtractor,
} = require('./extractor');

// ── interpreterParser ────────────────────────────────────────────────────
const {
  detectWeredevContext, detectVmDispatchLoop,
  dynamicOpcodeResolver,
  analyzeWeredevOpcodeBlock, extractWeredevOperands,
  _buildFlatConstPool, resolveWeredevZCalls,
  MAX_DISPATCH_ITERATIONS,
} = require('./interpreterParser');

// ── decompiler ───────────────────────────────────────────────────────────
const {
  vmDecompiler, reconstructedLuaBuilder,
  weredevAnalyze, weredevFullDecompile, weredevFullDecompileHandler,
  dispatcherFlatten, executeTrace, convertToSwitchCase, simplifyStateMachine,
} = require('./decompiler');

// ── detector (isWeredevObfuscated) ───────────────────────────────────────
const { isWeredevObfuscated } = require('../../core/detector');

// ════════════════════════════════════════════════════════════════════════
//  項目6: weredevDispatch — VM検出後のルーティング
//
//  luaPrinter は一切呼ばず、必ず decompiler.js の関数を経由する。
//
//  入力:
//    code          — 解析対象の Lua コード
//    vmTraceEntries — vmhook ログ (存在すれば項目15: 実行順優先)
//    bTableLog     — B テーブルログ
//    strLogEntries  — m() strlog
//    options       — { maxInstructions, forceStatic }
//
//  戻り値: decompiler.js の出力をそのまま返す
// ════════════════════════════════════════════════════════════════════════
function weredevDispatch(code, vmTraceEntries, bTableLog, strLogEntries, options) {
  // VM検出
  const detected = isWeredevObfuscated(code);
  if (!detected) {
    return { success: false, error: 'Weredev VMパターンが検出されませんでした', method: 'weredev_dispatch' };
  }

  // 項目6: luaPrinter を呼ばず decompiler.js の weredevAnalyze に直接委譲
  return weredevAnalyze(code, vmTraceEntries || [], bTableLog || {}, strLogEntries || [], options || {});
}

// ════════════════════════════════════════════════════════════════════════
//  全エクスポート
// ════════════════════════════════════════════════════════════════════════
module.exports = {
  // ── opcodeMap ──────────────────────────────────────────────────────
  LUA51_OPCODES,
  OPCODE_CATEGORIES,
  vmDecompileInstruction,
  vmTraceAnalyzer,
  buildOpcodeMapFromTrace,
  remapOpcodes,
  assignWeredevOpcodes,
  _inferOpNameFromOperands,
  resolveInstrConstants,

  // ── extractor ──────────────────────────────────────────────────────
  extractFirstLocalName,
  extractVmTableNames,
  extractVmTable,
  extractWeredevConstPool,
  extractWeredevZAccessor,
  _wdEscapeRegex,
  extractWeredevDispatchLoop,
  dumpBytecodeTables,
  vmBytecodeExtractor,

  // ── interpreterParser ──────────────────────────────────────────────
  detectWeredevContext,
  detectVmDispatchLoop,
  dynamicOpcodeResolver,
  analyzeWeredevOpcodeBlock,
  extractWeredevOperands,
  _buildFlatConstPool,
  resolveWeredevZCalls,
  MAX_DISPATCH_ITERATIONS,

  // ── decompiler ─────────────────────────────────────────────────────
  vmDecompiler,
  reconstructedLuaBuilder,
  weredevAnalyze,
  weredevFullDecompile,
  weredevFullDecompileHandler,
  dispatcherFlatten,          // 項目7
  executeTrace,               // 項目8
  convertToSwitchCase,        // 項目9
  simplifyStateMachine,       // 項目13

  // ── 項目6: VM検出後ルーター ────────────────────────────────────────
  weredevDispatch,
};
