// server.js — 司令塔
'use strict';

const express    = require('express');
const cors       = require('cors');
const { exec, execSync } = require('child_process');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');

// ─── モジュール ──────────────────────────────────────────────────────────
const luaPrinter    = require('./utils/luaPrinter');
const detector      = require('./core/detector');
const stringDecoder = require('./core/stringDecoder');
const astTools      = require('./core/astTools');
const logParser     = require('./vm/vmhook/logParser');
const weredevs      = require('./vm/weredevs/index');

// 名前空間展開
const {
  cacheGet, cacheSet, scoreLuaCode, stripComments, beautifyLua,
  parseLuaArrayElements, resolveLuaStringEscapes, stripLuaString,
  splitByComma, splitByConcat, hashCode,
} = luaPrinter;
const { loaderPatternDetected, vmDetector, isWeredevObfuscated, deobfuscateVmify } = detector;
const {
  evalLuaNumExpr, evalSimpleExpr, evalStringChar, evalArithWithEnv, evalExprWithEnv,
  deobfuscateSplitStrings, charDecoder, xorDecoder, deobfuscateXOR,
  staticCharDecoder, stringTransformDecoder, base64Detector, deobfuscateEncryptStrings,
  decodeEscapedString, decodeAllEscapedStrings, decodeStringBuilder,
} = stringDecoder;
const {
  CapturePool, evaluateExpressions, constantArrayResolver, deobfuscateConstantArray,
  constantCallEvaluator, mathEvaluator, deadBranchRemover,
  junkAssignmentCleaner, duplicateConstantReducer,
  advancedStaticDeobfuscate, deepStaticDeobfuscate, symbolicExecute, recursiveDeobfuscate,
} = astTools;
const {
  safeEnvPreamble, hookLoadstringCode, vmHookBootstrap,
  injectVmHook, runLuaWithHooks, parseDecodedOutputs,
  parseVmLogs, parseVmTrace, parseBTableLog, parseVTableLog,
  parseStrLog, parseStrCharLog, parseTConcatLog,
  saveVmTrace, parseBytecodeDump,
  VM_TRACE_THRESHOLD, checkWereDevDetected,
} = logParser;
const {
  LUA51_OPCODES, vmDecompileInstruction, vmTraceAnalyzer,
  buildOpcodeMapFromTrace, remapOpcodes,
  extractVmTableNames, extractVmTable,
  extractWeredevConstPool, extractWeredevDispatchLoop, extractWeredevZAccessor,
  dumpBytecodeTables, vmBytecodeExtractor,
  detectWeredevContext, resolveWeredevZCalls, detectVmDispatchLoop,
  vmDecompiler, weredevAnalyze, weredevFullDecompileHandler,
} = weredevs;

// ─── Express ─────────────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => {
  console.error('Express error:', err);
  res.status(500).json({ success: false, error: err.message });
});

const tempDir = path.join(__dirname, 'temp');
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

function checkLuaAvailable() {
  try { execSync('lua -v 2>&1', { timeout: 3000 }); return 'lua'; } catch {}
  try { execSync('luajit -v 2>&1', { timeout: 3000 }); return 'luajit'; } catch {}
  return null;
}

// Prometheus は Lua5.1 専用なので専用バイナリを探す
function checkLua51Available() {
  try { execSync('lua5.1 -v 2>&1', { timeout: 3000 }); return 'lua5.1'; } catch {}
  try { execSync('luajit -v 2>&1', { timeout: 3000 }); return 'luajit'; } catch {}
  // lua5.4 でも一応試す（動かない場合もある）
  try { execSync('lua -v 2>&1', { timeout: 3000 }); return 'lua'; } catch {}
  return null;
}
function checkPrometheusAvailable() {
  return fs.existsSync(path.join(__dirname, 'prometheus', 'cli.lua'))
      || fs.existsSync(path.join(__dirname, 'cli.lua'));
}

// ════════════════════════════════════════════════════════
//  STATUS  GET /api/status
// ════════════════════════════════════════════════════════

// ─── sandbox (MAX_DYNAMIC_SIZEに依存するためserver.jsに配置) ──────────
const MAX_DYNAMIC_SIZE = 512 * 1024; // 512KB
const DANGEROUS_PATTERNS = [
  /\bos\.execute\s*\(/g,
  /\bio\.popen\s*\(/g,
  /\bio\.open\s*\([^,)]+,\s*["']w/g,
  /\brequire\s*\(\s*["']socket/g,
  /\bloadfile\s*\(/g,
  /\bdofile\s*\(/g,
  /\bpackage\.loadlib\s*\(/g,
];

function sandboxFilter(code) {
  if(code.length>MAX_DYNAMIC_SIZE)
    return { safe:false, reason:`コードが大きすぎます (${(code.length/1024).toFixed(1)}KB > 512KB)`, code };
  let filtered=code;
  const removed=[];
  for(const pat of DANGEROUS_PATTERNS){
    if(pat.test(filtered)){
      filtered=filtered.replace(pat,m=>{ removed.push(m.replace(/\(/,'')); return '--[[REMOVED]]--'; });
      pat.lastIndex=0;
    }
  }
  return { safe:true, code:filtered, removed };
}

// ────────────────────────────────────────────────────────────────────────
//  #14  vmDetector  — while true do opcode=... のVMパターン検出
// ────────────────────────────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════════
//  BLOCK 2: vmDetector強化 / vmHookBootstrap / injectVmHook (#19-#33)
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
//  #20-#22  vmDetector 強化版 — MoonSec / Luraph / WereDev 検出
// ────────────────────────────────────────────────────────────────────────

// ─── API ルーティング ─────────────────────────────────────────────────
app.get('/api/status', (req, res) => {
  res.json({
    status: 'ok',
    lua: checkLuaAvailable() || 'not installed',
    prometheus: checkPrometheusAvailable() ? 'available' : 'not found',
    deobfuscateMethods: ['auto','advanced_static','eval_expressions','split_strings','xor','constant_array','dynamic','vmify','char_decoder','xor_decoder','math_eval','constant_call','str_transform','dead_branch','junk_clean','vm_detect','vm_extract','base64_detect','weredev_full_decompile'],
    obfuscatePresets:   ['Minify', 'Weak', 'Medium', 'Strong'],
    obfuscateSteps:     ['SplitStrings', 'EncryptStrings', 'ConstantArray', 'ProxifyLocals', 'WrapInFunction', 'Vmify'],
  });
});

// ════════════════════════════════════════════════════════
//  解読 API  POST /api/deobfuscate
// ════════════════════════════════════════════════════════
app.post('/api/deobfuscate', async (req, res) => {
  const { code, method } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });

  let result;
  switch (method) {
    case 'xor':             result = xorDecoder(code);                break;
    case 'split_strings':   result = deobfuscateSplitStrings(code);   break;
    case 'encrypt_strings': result = deobfuscateEncryptStrings(code); break;
    case 'constant_array':  result = constantArrayResolver(code);     break;
    case 'eval_expressions':result = evaluateExpressions(code);       break;
    case 'advanced_static': result = advancedStaticDeobfuscate(code); break;
    case 'char_decoder':    result = charDecoder(code);               break;
    case 'xor_decoder':     result = xorDecoder(code);                break;
    case 'math_eval':       result = mathEvaluator(code);             break;
    case 'constant_call':   result = constantCallEvaluator(code);     break;
    case 'str_transform':   result = stringTransformDecoder(code);    break;
    case 'dead_branch':     result = deadBranchRemover(code);         break;
    case 'junk_clean':      result = junkAssignmentCleaner(code);     break;
    case 'vm_detect':       result = { ...vmDetector(code), success: vmDetector(code).isVm }; break;
    case 'vm_extract':              result = vmBytecodeExtractor(code);              break;
    case 'weredev_full_decompile':  result = weredevFullDecompileHandler(code);       break;
    case 'base64_detect':           result = base64Detector(code, new CapturePool()); break;
    case 'vmify':           result = deobfuscateVmify(code);          break;
    case 'dynamic':         result = await tryDynamicExecution(code); break;
    case 'auto':
    default:                result = await autoDeobfuscate(code);    break;
  }

  res.json(result);
});

// 後方互換 (旧エンドポイント)
app.post('/deobfuscate', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(deobfuscateXOR(code));
});

// ════════════════════════════════════════════════════════
//  難読化 API  POST /api/obfuscate  (Prometheus)
// ════════════════════════════════════════════════════════
app.post('/api/obfuscate', async (req, res) => {
  const { code, preset, steps } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(await obfuscateWithPrometheus(code, { preset, steps }));
});

// ════════════════════════════════════════════════════════
//  VM難読化 API  POST /api/vm-obfuscate
// ════════════════════════════════════════════════════════
app.post('/api/vm-obfuscate', async (req, res) => {
  const { code, seed } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(await obfuscateWithCustomVM(code, { seed }));
});


// ════════════════════════════════════════════════════════
//  動的実行  —  Renderサーバー上のLuaを最大限活用
//
//  方針:
//   1. まず動的実行を試みる（これがメイン）
//   2. 動的実行が失敗した場合のみ静的解析にフォールバック
//   3. 多段難読化に対応（動的実行の結果を再帰的に動的実行）
//   4. アンチダンプ・アンチデバッグを無効化してから実行
// ════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════
//  dynamicDecode — #2/#3/#4/#7/#9 統合: loadstring hookedで __DECODED__ dump
// ════════════════════════════════════════════════════════════════════════

// ─── 動的解析 (BLOCK 4) ──────────────────────────────────────────────
//  BLOCK 4: dynamicDecode v2 + autoDeobfuscate v5 (#1-#57 統合)
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
//  dynamicDecode v2  (#2/#4-#11/#23-#25)
// ────────────────────────────────────────────────────────────────────────
async function dynamicDecode(code) {
  const luaBin = checkLuaAvailable();
  if (!luaBin) return { success: false, error: 'Luaがインストールされていません', method: 'dynamic_decode' };

  const filtered = sandboxFilter(code);
  if (!filtered.safe) return { success: false, error: filtered.reason, method: 'dynamic_decode' };
  if (filtered.removed.length > 0) console.log('[DynDec] 危険関数除去:', filtered.removed.join(', '));

  // preamble: safeEnv + hookLoadstring + vmHookBootstrap
  const preamble = safeEnvPreamble + '\n' + hookLoadstringCode + '\n' + vmHookBootstrap;

  // #23: vmDetector(codeToRun) — hook注入後のコードに対して検出
  let codeToRun = filtered.code;
  let vmHookInjected = false, bytecodeCandidates = [];

  const vmInfoPre = vmDetector(codeToRun);  // hook前の初期検出

  // VM検出後に hook注入
  if (vmInfoPre.isVm || vmInfoPre.isWereDev || vmInfoPre.isMoonSec || vmInfoPre.isLuraph) {
    // #24: /while\s+true\s+do|repeat\s+until/ に拡張
    const hasVmLoop = /while\s+true\s+do|repeat\s+until/.test(codeToRun);
    if (hasVmLoop) {
      const hookResult = injectVmHook(codeToRun, vmInfoPre);
      codeToRun = hookResult.code;
      vmHookInjected = hookResult.injected;
    }
    const dumpResult = dumpBytecodeTables(codeToRun);
    codeToRun = dumpResult.code;
    bytecodeCandidates = dumpResult.candidates;
  }

  // #23: hook注入後のコードで再検出
  const vmInfo = vmDetector(codeToRun);

  const fullCode = preamble + '\n' + codeToRun + '\n' + vmDumpFooter;
  const safeFullCode = fullCode.replace(/\]\]/g, ']] ');
  const tempFile = path.join(tempDir, `dyndec_${Date.now()}_${Math.random().toString(36).substring(7)}.lua`);

  const wrapper = `
-- ══ YAJU dynamicDecode v3 Wrapper ══
-- アンチダンプ・アンチデバッグを無効化
pcall(function()
  if debug then
    debug.sethook=function() end; debug.getinfo=nil
    debug.getlocal=nil; debug.setlocal=nil
    debug.getupvalue=nil; debug.setupvalue=nil
  end
end)
pcall(function()
  if getfenv then
    local env=getfenv()
    env.saveinstance=nil; env.dumpstring=nil; env.save_instance=nil
  end
end)

local __obf_code = [[
${safeFullCode}
]]

-- [1] preamble 内のフックが確実に有効になるよう
-- wrapper レベルでも loadstring / load を直接上書き
local __orig_ls_outer = loadstring or load
local function __outer_hook(c, ...)
  if type(c) == "string" and #c > 10 then
    io.write("\\n__DECODED_START_0__\\n")
    io.write(c)
    io.write("\\n__DECODED_END_0__\\n")
    io.flush()
  end
  return __orig_ls_outer(c, ...)
end
loadstring = __outer_hook
load       = __outer_hook
if rawset then
  pcall(function() rawset(_G, "loadstring", __outer_hook) end)
  pcall(function() rawset(_G, "load",       __outer_hook) end)
end

local __ok, __err = pcall(function()
  local chunk, err = __orig_ls_outer(__obf_code)
  if not chunk then error("parse error: " .. tostring(err)) end
  chunk()
end)

if not __ok then
  io.write("\\n__EXEC_ERROR__:" .. tostring(__err) .. "\\n")
end
`;

  return new Promise(resolve => {
    fs.writeFileSync(tempFile, wrapper, 'utf8');

    // #25: タイムアウト 3000ms
    exec(`${luaBin} ${tempFile}`, { timeout: 3000, maxBuffer: 50 * 1024 * 1024 }, (error, stdout, stderr) => {
      try { fs.unlinkSync(tempFile); } catch {}

      // __DECODED__ 抽出
      const decoded = parseDecodedOutputs(stdout);

      // 旧 __VMLOG__ 形式のトレース（互換）
      const vmTrace      = parseVmLogs(stdout);
      // [1] 新 __VMTRACE__ 形式（Weredev l/A/B/C/regs フォーマット）
      const vmTraceNew   = parseVmTrace(stdout);
      // [2] B/V テーブルパース（Weredev bytecode / registers）
      const bTableLog    = parseBTableLog(stdout);
      const vTableLog    = parseVTableLog(stdout);
      // [3] m() string accessor ログ
      const strLog       = parseStrLog(stdout);
      // string.char / table.concat キャプチャ
      const strCharLog   = parseStrCharLog(stdout);
      const tConcatLog   = parseTConcatLog(stdout);
      const bytecodeDump = parseBytecodeDump(stdout);

      // vmTrace 統合（新形式優先、フォールバックは旧形式）
      // 新形式エントリは l/A/B/C/pc フィールドを持つ
      const traceEntries = vmTraceNew.found ? vmTraceNew.entries : [];
      const traceForAnalysis = vmTraceNew.found
        ? traceEntries.map(e => ({ ip: e.pc || 0, op: e.l, arg1: e.A, arg2: e.B, arg3: e.C }))
        : vmTrace;

      const wereDevDetected = checkWereDevDetected(traceForAnalysis) || isWeredevObfuscated(codeToRun);
      if (traceForAnalysis.length > 0) saveVmTrace(traceForAnalysis, Date.now());

      // ── Weredev 専用解析 (項目1〜10) ──────────────────────────────────
      const weredevResult = weredevAnalyze(
        codeToRun,
        traceEntries.length > 0 ? traceEntries : traceForAnalysis,
        bTableLog,
        strLog.found ? strLog.entries : [],
        { maxInstructions: 100000 }  // 項目7
      );

      const vmAnalysis = {
        vmTrace:          traceForAnalysis,
        vmTraceRaw:       vmTraceNew.found  ? vmTraceNew  : null,
        bTable:           bTableLog.found   ? bTableLog   : null,
        vTable:           vTableLog.found   ? vTableLog   : null,
        strLog:           strLog.found      ? strLog      : null,
        strCharLog:       strCharLog.found  ? strCharLog  : null,
        tConcatLog:       tConcatLog.found  ? tConcatLog  : null,
        bytecodeDump,
        wereDevDetected,
        vmHookInjected,
        bytecodeCandidates,
        vmInfo,
        traceCount:       vmTraceNew.found  ? vmTraceNew.count : vmTrace.length,
        bTableCount:      bTableLog.found   ? bTableLog.count  : 0,
        strLogCount:      strLog.found      ? strLog.count      : 0,
        // Weredev 専用解析結果 (項目1〜10)
        weredev:          weredevResult,
      };
      if (wereDevDetected) {
        vmAnalysis.traceAnalysis  = vmTraceAnalyzer(traceForAnalysis);
        // remapped opcodeMap を優先使用
        const finalOpcodeMap = {
          map: weredevResult.remapped,
          opcodeExecutionMap: vmAnalysis.traceAnalysis.opcodeMap &&
                              vmAnalysis.traceAnalysis.opcodeMap.opcodeExecutionMap || {},
        };
        vmAnalysis.reconstruction = vmDecompiler(
          traceForAnalysis, bytecodeDump, finalOpcodeMap
        );
        // 項目6の vmDecompileInstruction による疑似コードも保持
        if (weredevResult.decompiledCode && weredevResult.decompiledCode.length > 50) {
          vmAnalysis.weredevDecompiled = weredevResult.decompiledCode;
        }
      }

      // __DECODED__ が取れた場合
      if (decoded.best && decoded.best.length >= 10) {
        return resolve({
          success: true,
          result: decoded.best,
          allDecoded: decoded.all.map(d => d.code),
          decodedCount: decoded.all.length,
          method: 'dynamic_decode',
          vmAnalysis: (vmTrace.length > 0 || wereDevDetected) ? vmAnalysis : undefined,
        });
      }

      // VMトレース再構築が取れた場合（vmDecompiler の結果）
      if (wereDevDetected && vmAnalysis.reconstruction && vmAnalysis.reconstruction.success) {
        const pseudoCode = vmAnalysis.reconstruction.pseudoCode || '';
        if (pseudoCode.length >= 10) {
          return resolve({
            success: true,
            result: pseudoCode,
            method: 'dynamic_decode_vm',
            vmAnalysis,
            WereDevVMDetected: true,
          });
        }
      }

      // 項目6/7: weredevAnalyze の疑似コードをフォールバックとして使用
      if (wereDevDetected && vmAnalysis.weredevDecompiled && vmAnalysis.weredevDecompiled.length >= 50) {
        return resolve({
          success: true,
          result: vmAnalysis.weredevDecompiled,
          method: 'weredev_decompile',
          vmAnalysis,
          WereDevVMDetected: true,
        });
      }

      // [5] __EXEC_ERROR__ の安全な抽出 (indexOf で存在チェック)
      let errMsg = '';
      if (stdout && stdout.indexOf('__EXEC_ERROR__:') !== -1) {
        const errStart = stdout.indexOf('__EXEC_ERROR__:') + '__EXEC_ERROR__:'.length;
        const errEnd   = stdout.indexOf('\n', errStart);
        errMsg = (errEnd !== -1 ? stdout.substring(errStart, errEnd) : stdout.substring(errStart)).substring(0, 300);
      } else if (stderr) {
        errMsg = stderr.substring(0, 300);
      }

      resolve({
        success: false,
        error: errMsg || 'loadstringが呼ばれませんでした',
        method: 'dynamic_decode',
        vmAnalysis: vmTrace.length > 0 ? vmAnalysis : undefined,
      });
    });
  });
}

async function tryDynamicExecution(code) {
  const luaBin = checkLuaAvailable();
  if (!luaBin) return { success: false, error: 'Luaがインストールされていません', method: 'dynamic' };

  const tempFile = path.join(tempDir, `obf_${Date.now()}_${Math.random().toString(36).substring(7)}.lua`);

  // ]] が含まれる場合のエスケープ
  const safeCode = code.replace(/\]\]/g, '] ]');

  const wrapper = `
-- ══════════════════════════════════════════
--  YAJU Deobfuscator - Dynamic Execution Wrapper
-- ══════════════════════════════════════════

-- 全キャプチャを格納するテーブル（多段対応）
local __captures = {}
local __capture_count = 0
local __original_loadstring = loadstring or load
local __original_load = load or loadstring

-- アンチダンプ・アンチデバッグを無効化
pcall(function()
  if debug then
    debug.sethook = function() end
    debug.getinfo = nil
    debug.getlocal = nil
    debug.setlocal = nil
    debug.getupvalue = nil
    debug.setupvalue = nil
  end
end)
pcall(function()
  if getfenv then
    local env = getfenv()
    env.saveinstance = nil
    env.dumpstring = nil
    env.save_instance = nil
  end
end)

-- loadstring / load を完全フック
local function __hook(code_str, ...)
  if type(code_str) == "string" and #code_str > 20 then
    __capture_count = __capture_count + 1
    __captures[__capture_count] = code_str
  end
  return __original_loadstring(code_str, ...)
end

_G.loadstring = __hook
_G.load       = __hook
if rawset then
  pcall(function() rawset(_G, "loadstring", __hook) end)
  pcall(function() rawset(_G, "load", __hook) end)
end

-- 難読化コードを実行
local __obf_code = [[
${safeCode}
]]

local __ok, __err = pcall(function()
  local chunk, err = __original_loadstring(__obf_code)
  if not chunk then error("parse error: " .. tostring(err)) end
  chunk()
end)

-- キャプチャ結果を出力（最後にキャプチャされたものが最も解読されたもの）
if __capture_count > 0 then
  -- 最も長い（＝最も展開された）コードを選択
  local best = __captures[1]
  for i = 2, __capture_count do
    if #__captures[i] > #best then best = __captures[i] end
  end
  io.write("__CAPTURED_START__")
  io.write(best)
  io.write("__CAPTURED_END__")
  -- 多段情報も出力
  if __capture_count > 1 then
    io.write("__LAYERS__:" .. tostring(__capture_count))
  end
else
  io.write("__NO_CAPTURE__")
  if not __ok then
    io.write("__ERROR__:" .. tostring(__err))
  end
end
`;

  return new Promise(resolve => {
    fs.writeFileSync(tempFile, wrapper, 'utf8');

    exec(`${luaBin} ${tempFile}`, { timeout: 20000, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      try { fs.unlinkSync(tempFile); } catch {}

      // キャプチャ成功
      if (stdout.includes('__CAPTURED_START__') && stdout.includes('__CAPTURED_END__')) {
        const start    = stdout.indexOf('__CAPTURED_START__') + '__CAPTURED_START__'.length;
        const end      = stdout.indexOf('__CAPTURED_END__');
        const captured = stdout.substring(start, end).trim();

        if (captured && captured.length > 5) {
          // [4] captured が元コードとほぼ同じ（長さ差5%以内）なら新レイヤーと判断しない
          const originalLen = code.length;
          const capturedLen = captured.length;
          const diffRatio = Math.abs(capturedLen - originalLen) / Math.max(originalLen, 1);
          if (diffRatio <= 0.05 && captured === code.trim()) {
            return resolve({ success: false, error: 'captured が元コードと同一のため停止', method: 'dynamic' });
          }
          const layerMatch = stdout.match(/__LAYERS__:(\d+)/);
          const layers = layerMatch ? parseInt(layerMatch[1]) : 1;
          return resolve({ success: true, result: captured, layers, method: 'dynamic' });
        }
      }

      // エラー情報
      if (stdout.includes('__ERROR__:')) {
        const errMsg = stdout.split('__ERROR__:')[1] || '';
        return resolve({ success: false, error: 'Luaエラー: ' + errMsg.substring(0, 300), method: 'dynamic' });
      }

      if (error && stderr) {
        return resolve({ success: false, error: '実行エラー: ' + stderr.substring(0, 300), method: 'dynamic' });
      }

      resolve({ success: false, error: 'loadstring()が呼ばれませんでした（VM系難読化の可能性）', method: 'dynamic' });
    });
  });
}

// ────────────────────────────────────────────────────────────────────────
//  autoDeobfuscate v5  (#1-#20, #56/#57 最終処理)
// ────────────────────────────────────────────────────────────────────────
async function autoDeobfuscate(code) {
  const results = [];
  let current = code;
  const luaBin = checkLuaAvailable();

  // ① メイン: 動的実行
  if (luaBin) {
    const dynRes = await tryDynamicExecution(current);
    results.push({ step: '動的実行 (1回目)', ...dynRes });

    if (dynRes.success && dynRes.result) {
      current = dynRes.result;

      // ② 多段難読化対応: 結果をさらに動的実行（最大3回）
      for (let round = 2; round <= 4; round++) {
        // 結果がまだ難読化されていそうか確認（loadstringやBase64の特徴があるか）
        const stillObfuscated = /loadstring|load\s*\(|[A-Za-z0-9+/]{60,}={0,2}/.test(current);
        if (!stillObfuscated) break;

        const dynRes2 = await tryDynamicExecution(current);
        results.push({ step: `動的実行 (${round}回目)`, ...dynRes2 });
        if (dynRes2.success && dynRes2.result && dynRes2.result !== current) {
          current = dynRes2.result;
        } else {
          break; // これ以上変化しないので停止
        }
      }
    } else {
      // ③ 動的実行が失敗 → 静的解析で前処理してから再挑戦
      results.push({ step: '静的解析フォールバック開始', success: true, result: current, method: 'info' });

      const staticSteps = [
        { name: 'SplitStrings',    fn: deobfuscateSplitStrings },
        { name: 'EncryptStrings',  fn: deobfuscateEncryptStrings },
        { name: 'EvalExpressions', fn: evaluateExpressions },
        { name: 'ConstantArray',   fn: deobfuscateConstantArray },
        { name: 'XOR',             fn: deobfuscateXOR },
      ];

      let staticChanged = false;
      for (const step of staticSteps) {
        const res = step.fn(current);
        results.push({ step: step.name, ...res });
        if (res.success && res.result && res.result !== current) {
          current = res.result;
          staticChanged = true;
        }
      }

      // ④ 静的解析で変化があれば動的実行を再試行
      if (staticChanged) {
        const dynRes3 = await tryDynamicExecution(current);
        results.push({ step: '動的実行 (静的解析後)', ...dynRes3 });
        if (dynRes3.success && dynRes3.result) current = dynRes3.result;
      }
    }
  } else {
    // Luaなし → 静的解析のみ
    results.push({ step: '動的実行', success: false, error: 'Luaがインストールされていません', method: 'dynamic' });
    const staticSteps = [
      { name: 'SplitStrings',    fn: deobfuscateSplitStrings },
      { name: 'EncryptStrings',  fn: deobfuscateEncryptStrings },
      { name: 'EvalExpressions', fn: evaluateExpressions },
      { name: 'ConstantArray',   fn: deobfuscateConstantArray },
      { name: 'XOR',             fn: deobfuscateXOR },
      { name: 'Vmify',           fn: deobfuscateVmify },
    ];
    for (const step of staticSteps) {
      const res = step.fn(current);
      results.push({ step: step.name, ...res });
      if (res.success && res.result && res.result !== current) current = res.result;
    }
  }

  return { success: results.some(r => r.success), steps: results, finalCode: current };
}



// ════════════════════════════════════════════════════════
//  Prometheus 難読化
// ════════════════════════════════════════════════════════

// ─── 難読化エンジン ───────────────────────────────────────────────────
function obfuscateWithPrometheus(code, options = {}) {
  return new Promise(resolve => {
    // PrometheusはLua5.1専用 → lua5.1 → luajit → lua の順で探す
    const luaBin = checkLua51Available();
    if (!luaBin) { resolve({ success: false, error: 'lua5.1またはLuaJITがインストールされていません' }); return; }

    const cliPath = fs.existsSync(path.join(__dirname, 'prometheus', 'cli.lua'))
      ? path.join(__dirname, 'prometheus', 'cli.lua')
      : path.join(__dirname, 'cli.lua');

    if (!fs.existsSync(cliPath)) {
      resolve({ success: false, error: 'Prometheusが見つかりません' });
      return;
    }

    const tmpIn  = path.join(tempDir, `prom_in_${crypto.randomBytes(8).toString('hex')}.lua`);
    const tmpOut = path.join(tempDir, `prom_out_${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(tmpIn, code);

    const preset = options.preset || 'Medium';
    // stepsは現状Prometheusのargとして渡すと問題が起きるため使わない
    // preset のみで制御する
    const cmd = `${luaBin} ${cliPath} --preset ${preset} ${tmpIn} --out ${tmpOut}`;

    console.log('[Prometheus] cmd:', cmd);
    console.log('[Prometheus] input preview:', JSON.stringify(code.substring(0, 120)));

    exec(cmd, { timeout: 30000, cwd: path.dirname(cliPath) }, (err, stdout, stderr) => {
      try { fs.unlinkSync(tmpIn); } catch {}
      const errText = (stderr || '').trim();
      const outText = (stdout || '').trim();
      console.log('[Prometheus] stdout:', outText.substring(0, 200));
      console.log('[Prometheus] stderr:', errText.substring(0, 200));
      try {
        if (err) {
          // エラー内容をそのままフロントに返す
          resolve({ success: false, error: 'Lua: ' + errText });
          return;
        }
        if (!fs.existsSync(tmpOut)) {
          resolve({ success: false, error: 'Prometheusが出力ファイルを生成しませんでした。stderr: ' + errText });
          return;
        }
        const result = fs.readFileSync(tmpOut, 'utf8');
        if (!result || result.trim().length === 0) {
          resolve({ success: false, error: 'Prometheusの出力が空でした' });
          return;
        }
        resolve({ success: true, result, preset });
      } finally {
        try { fs.unlinkSync(tmpOut); } catch {}
      }
    });
  });
}

// ════════════════════════════════════════════════════════
//  古い一時ファイルのクリーンアップ
// ════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════
//  カスタムVM難読化
//  Renderサーバー上のLuaで実行される独自VMを生成する
//
//  フロー:
//   1. 入力Luaコードをサーバーに送る
//   2. vm_obfuscator.luaがコードをVM命令列に変換
//      - luacが使える場合: バイトコード → XOR暗号化 → VMランタイム
//      - luacがない場合: ソース → 加算暗号化 → VMランタイム
//   3. 生成されたVMコード（独自インタープリタ付き）を返す
// ════════════════════════════════════════════════════════
function obfuscateWithCustomVM(code, options = {}) {
  return new Promise(resolve => {
    const luaBin = checkLuaAvailable();
    if (!luaBin) {
      resolve({ success: false, error: 'Luaがインストールされていません' });
      return;
    }

    // vm_obfuscator.lua の場所を確認
    const vmScript = path.join(__dirname, 'vm_obfuscator.lua');
    if (!fs.existsSync(vmScript)) {
      resolve({ success: false, error: 'vm_obfuscator.luaが見つかりません' });
      return;
    }

    const seed = options.seed || (Math.floor(Math.random() * 900000) + 100000);
    const tmpIn  = path.join(tempDir, `vm_in_${crypto.randomBytes(8).toString('hex')}.lua`);
    const tmpOut = path.join(tempDir, `vm_out_${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(tmpIn, code, 'utf8');

    const cmd = `${luaBin} ${vmScript} ${tmpIn} --out ${tmpOut} --seed ${seed}`;
    console.log('[VM] cmd:', cmd);

    exec(cmd, { timeout: 30000, cwd: __dirname }, (err, stdout, stderr) => {
      try { fs.unlinkSync(tmpIn); } catch {}

      const outText = (stdout || '').trim();
      const errText = (stderr || '').trim();
      console.log('[VM] stdout:', outText.substring(0, 200));
      if (errText) console.log('[VM] stderr:', errText.substring(0, 200));

      if (err) {
        resolve({ success: false, error: 'VM難読化エラー: ' + (errText || err.message) });
        return;
      }

      // vm_obfuscator.lua は成功時 "OK:<outfile>" を stdout に出力する
      if (!outText.startsWith('OK:') && !fs.existsSync(tmpOut)) {
        resolve({ success: false, error: 'VM難読化失敗: ' + (errText || outText || '出力なし') });
        return;
      }

      try {
        if (!fs.existsSync(tmpOut)) {
          resolve({ success: false, error: '出力ファイルが見つかりません' });
          return;
        }
        const result = fs.readFileSync(tmpOut, 'utf8');
        if (!result || result.trim().length === 0) {
          resolve({ success: false, error: 'VM難読化の出力が空でした' });
          return;
        }
        resolve({ success: true, result, seed, method: 'custom_vm' });
      } finally {
        try { fs.unlinkSync(tmpOut); } catch {}
      }
    });
  });
}

// ════════════════════════════════════════════════════════════════════════

// ─── 定期クリーンアップ + サーバー起動 ────────────────────────────────
setInterval(() => {
  const now = Date.now();
  fs.readdir(tempDir, (err, files) => {
    if (err) return;
    files.forEach(file => {
      const fp = path.join(tempDir, file);
      fs.stat(fp, (err, stats) => {
        if (!err && now - stats.mtimeMs > 10 * 60 * 1000) fs.unlink(fp, () => {});
      });
    });
  });
}, 5 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`🔥 Lua Obfuscator/Deobfuscator Server running on port ${PORT}`);
  console.log(`   Lua:        ${checkLuaAvailable() || 'NOT FOUND'}`);
  console.log(`   Prometheus: ${checkPrometheusAvailable() ? 'OK' : 'NOT FOUND (optional)'}`);
});
