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
  safeEnvPreamble, hookLoadstringCode, vmHookBootstrap, vmDumpFooter,
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

// ════════════════════════════════════════════════════════
//  VMhook ログ グローバルストア  (別 Render サービス不要・同一プロセス完結)
//
//  構造:
//    global.vmLogs      — セッション横断の全 opcode ログ配列
//    global.vmSessions  — { sessionId → { logs[], meta{} } }
//    global.recordOpcodeLog(entry) — decompiler.js から呼ばれるフック
// ════════════════════════════════════════════════════════
global.vmLogs     = [];          // フラットなログ全体 (最新 VM_LOGS_MAX 件)
global.vmSessions = {};          // セッション別ログ

const VM_LOGS_MAX      = 5000;   // フラット配列の上限
const VM_SESSION_MAX   = 50;     // セッション保持数の上限
const VM_SESSION_LOG_MAX = 2000; // 1セッションあたりのログ上限

// ── 現在アクティブなセッション ID (executeTrace 呼び出し単位で切り替わる) ──
let _currentSessionId = null;

// ── グローバルフック: decompiler.js の executeTrace ループ内から呼ばれる ──
// opcode 実行直前に { pc, opcode, opName, A, B, C, registers } が渡される
global.recordOpcodeLog = function recordOpcodeLog(entry) {
  const record = { ...entry, _ts: Date.now(), _sid: _currentSessionId };

  // フラット配列に追記
  global.vmLogs.push(record);
  if (global.vmLogs.length > VM_LOGS_MAX) {
    global.vmLogs = global.vmLogs.slice(-VM_LOGS_MAX);
  }

  // セッション別配列に追記
  if (_currentSessionId && global.vmSessions[_currentSessionId]) {
    const sess = global.vmSessions[_currentSessionId];
    sess.logs.push(record);
    if (sess.logs.length > VM_SESSION_LOG_MAX) {
      sess.logs = sess.logs.slice(-VM_SESSION_LOG_MAX);
    }
    sess.meta.lastPc     = entry.pc;
    sess.meta.logCount   = sess.logs.length;
    sess.meta.updatedAt  = record._ts;
  }
};

// ── セッション開始 (dynamicDecode / tryDynamicExecution の冒頭で呼ぶ) ──
function beginVmSession(label) {
  const sid = `${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  _currentSessionId = sid;
  global.vmSessions[sid] = {
    id:   sid,
    label: label || 'unnamed',
    logs:  [],
    meta:  { startedAt: Date.now(), logCount: 0, lastPc: null, updatedAt: null },
  };
  // 古いセッションを削除
  const keys = Object.keys(global.vmSessions);
  if (keys.length > VM_SESSION_MAX) {
    const oldest = keys.slice(0, keys.length - VM_SESSION_MAX);
    oldest.forEach(k => delete global.vmSessions[k]);
  }
  return sid;
}

// ── セッション終了 ────────────────────────────────────────────────────────
function endVmSession(sid, result) {
  if (sid && global.vmSessions[sid]) {
    const meta       = global.vmSessions[sid].meta;
    meta.endedAt     = Date.now();
    meta.durationMs  = meta.endedAt - meta.startedAt;
    meta.success     = result && result.success;
    meta.method      = result && result.method;
  }
  _currentSessionId = null;
}

// ── pushVmLog: 旧来の高レベルログ (traceCount / method 単位) ────────────
function pushVmLog(logEntry) {
  // セッションが終了済みなら durationMs を自動付与
  const sid  = logEntry._sid || _currentSessionId;
  const sess = sid && global.vmSessions[sid];
  const durationMs = sess && sess.meta.durationMs != null
    ? sess.meta.durationMs
    : undefined;
  global.vmLogs.push({
    ...logEntry,
    _ts:        Date.now(),
    _type:      'session_summary',
    durationMs: logEntry.durationMs != null ? logEntry.durationMs : durationMs,
  });
  if (global.vmLogs.length > VM_LOGS_MAX) {
    global.vmLogs = global.vmLogs.slice(-VM_LOGS_MAX);
  }
}

// ── MoonSec V3 デコンパイラのパス ─────────────────────────────────────────
// プロジェクトルートに moonsecv3decompiler.lua を配置すること
const DECOMPILER_LUA = path.join(__dirname, 'moonsecv3decompiler.lua');

// ────────────────────────────────────────────────────────────────────────
//  ユーティリティ
// ────────────────────────────────────────────────────────────────────────
function makeTempId() {
  return `${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

function safeUnlink(filePath) {
  try { fs.unlinkSync(filePath); } catch (_) {}
}


function checkLuaAvailable() {
  try { execSync('lua -v 2>&1', { timeout: 3000 }); return 'lua'; } catch {}
  try { execSync('luajit -v 2>&1', { timeout: 3000 }); return 'luajit'; } catch {}
  return null;
}

function checkLua51Available() {
  try { execSync('lua5.1 -v 2>&1', { timeout: 3000 }); return 'lua5.1'; } catch {}
  try { execSync('luajit -v 2>&1', { timeout: 3000 }); return 'luajit'; } catch {}
  try { execSync('lua -v 2>&1', { timeout: 3000 }); return 'lua'; } catch {}
  return null;
}

function checkPrometheusAvailable() {
  return fs.existsSync(path.join(__dirname, 'prometheus', 'cli.lua'))
      || fs.existsSync(path.join(__dirname, 'cli.lua'));
}

// ────────────────────────────────────────────────────────────────────────
//  sandbox
// ────────────────────────────────────────────────────────────────────────
const MAX_DYNAMIC_SIZE = 512 * 1024;
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
  if (code.length > MAX_DYNAMIC_SIZE)
    return { safe: false, reason: `コードが大きすぎます (${(code.length/1024).toFixed(1)}KB > 512KB)`, code };
  let filtered = code;
  const removed = [];
  for (const pat of DANGEROUS_PATTERNS) {
    if (pat.test(filtered)) {
      filtered = filtered.replace(pat, m => { removed.push(m.replace(/\(/, '')); return '--[[REMOVED]]--'; });
      pat.lastIndex = 0;
    }
  }
  return { safe: true, code: filtered, removed };
}

// ════════════════════════════════════════════════════════
//  GET /api/status
// ════════════════════════════════════════════════════════
app.get('/api/status', (req, res) => {
  res.json({
    status: 'ok',
    lua: checkLuaAvailable() || 'not installed',
    prometheus: checkPrometheusAvailable() ? 'available' : 'not found',
    decompiler: fs.existsSync(DECOMPILER_LUA) ? 'available' : 'not found',
    deobfuscateMethods: [
      'auto', 'advanced_static', 'eval_expressions', 'split_strings', 'xor',
      'constant_array', 'dynamic', 'vmify', 'char_decoder', 'xor_decoder',
      'math_eval', 'constant_call', 'str_transform', 'dead_branch', 'junk_clean',
      'vm_detect', 'vm_extract', 'base64_detect', 'weredev_full_decompile',
    ],
    obfuscatePresets: ['Minify', 'Weak', 'Medium', 'Strong'],
    obfuscateSteps:   ['SplitStrings', 'EncryptStrings', 'ConstantArray', 'ProxifyLocals', 'WrapInFunction', 'Vmify'],
  });
});

// ════════════════════════════════════════════════════════
//  GET /vmhook-logs  — VMhook opcode ログ一覧
//
//  クエリパラメータ:
//    limit   : 取得件数上限 (デフォルト 200, 最大 5000)
//    since   : _ts がこの値(ms)以降のエントリのみ
//    opcode  : opName でフィルタ (例: "CALL")
//    sid     : セッション ID でフィルタ
//    clear   : "1" → 取得後に global.vmLogs をリセット
//    type    : "opcode" | "summary" | "all" (デフォルト: all)
// ════════════════════════════════════════════════════════
app.get('/vmhook-logs', (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit  || '200'), VM_LOGS_MAX);
  const since  = parseInt(req.query.since  || '0');
  const opcode = req.query.opcode || null;
  const sid    = req.query.sid    || null;
  const type   = req.query.type   || 'all';
  const clear  = req.query.clear  === '1';

  let logs = [...global.vmLogs];

  if (since  > 0)           logs = logs.filter(e => e._ts >= since);
  if (opcode)               logs = logs.filter(e => e.opName === opcode || String(e.opcode) === opcode);
  if (sid)                  logs = logs.filter(e => e._sid  === sid);
  if (type === 'opcode')    logs = logs.filter(e => e._type !== 'session_summary');
  if (type === 'summary')   logs = logs.filter(e => e._type === 'session_summary');
  logs = logs.slice(-limit);

  const totalBefore = global.vmLogs.length;
  if (clear) { global.vmLogs = []; global.vmSessions = {}; }

  res.json({
    success:  true,
    count:    logs.length,
    total:    totalBefore,
    sessions: Object.keys(global.vmSessions).length,
    logs,
  });
});

// ════════════════════════════════════════════════════════
//  GET /vmhook-logs/sessions  — セッション一覧
// ════════════════════════════════════════════════════════
app.get('/vmhook-logs/sessions', (req, res) => {
  const sessions = Object.values(global.vmSessions).map(s => ({
    id:         s.id,
    label:      s.label,
    logCount:   s.meta.logCount,
    startedAt:  s.meta.startedAt,
    endedAt:    s.meta.endedAt   || null,
    durationMs: s.meta.durationMs != null ? s.meta.durationMs : null,
    success:    s.meta.success,
    method:     s.meta.method,
  })).reverse();   // 新しい順
  res.json({ success: true, count: sessions.length, sessions });
});

// ════════════════════════════════════════════════════════
//  GET /vmhook-logs/session/:sid  — セッション別詳細ログ
//
//  クエリパラメータ:
//    limit  : ログ件数上限 (デフォルト 500)
//    offset : 先頭スキップ数
// ════════════════════════════════════════════════════════
app.get('/vmhook-logs/session/:sid', (req, res) => {
  const sess = global.vmSessions[req.params.sid];
  if (!sess) return res.status(404).json({ success: false, error: 'セッションが見つかりません' });

  const limit  = Math.min(parseInt(req.query.limit  || '500'), VM_SESSION_LOG_MAX);
  const offset = parseInt(req.query.offset || '0');
  const logs   = sess.logs.slice(offset, offset + limit);

  res.json({
    success:  true,
    id:       sess.id,
    label:    sess.label,
    meta:     sess.meta,
    count:    logs.length,
    total:    sess.logs.length,
    logs,
  });
});

// ════════════════════════════════════════════════════════
//  GET /log  — VMhook ログビューア (log.html を同一サーバーで配信)
// ════════════════════════════════════════════════════════
app.get('/log', (req, res) => {
  const logHtmlPath = path.join(__dirname, 'public', 'log.html');
  if (fs.existsSync(logHtmlPath)) {
    return res.sendFile(logHtmlPath);
  }
  // public/log.html が存在しない場合はインライン HTML を返す
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(buildInlineLogHtml());
});

// ════════════════════════════════════════════════════════
//  POST /api/deobfuscate  — 解読
// ════════════════════════════════════════════════════════
app.post('/api/deobfuscate', async (req, res) => {
  const { code, method } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });

  let result;
  try {
    switch (method) {
      case 'xor':                    result = xorDecoder(code);                          break;
      case 'split_strings':          result = deobfuscateSplitStrings(code);             break;
      case 'encrypt_strings':        result = deobfuscateEncryptStrings(code);           break;
      case 'constant_array':         result = constantArrayResolver(code);               break;
      case 'eval_expressions':       result = evaluateExpressions(code);                 break;
      case 'advanced_static':        result = advancedStaticDeobfuscate(code);           break;
      case 'char_decoder':           result = charDecoder(code);                         break;
      case 'xor_decoder':            result = xorDecoder(code);                          break;
      case 'math_eval':              result = mathEvaluator(code);                       break;
      case 'constant_call':          result = constantCallEvaluator(code);               break;
      case 'str_transform':          result = stringTransformDecoder(code);              break;
      case 'dead_branch':            result = deadBranchRemover(code);                   break;
      case 'junk_clean':             result = junkAssignmentCleaner(code);               break;
      case 'vm_detect':              result = { ...vmDetector(code), success: vmDetector(code).isVm }; break;
      case 'vm_extract':             result = vmBytecodeExtractor(code);                 break;
      case 'weredev_full_decompile': result = weredevFullDecompileHandler(code);         break;
      case 'base64_detect':          result = base64Detector(code, new CapturePool());  break;
      case 'vmify':                  result = deobfuscateVmify(code);                    break;
      case 'dynamic': {
        // mode 決定: Weredevs検出 → 'weredevs' / それ以外 → 'dynamic'
        const dynMode = isWeredevWrapper(code) ? 'weredevs' : 'dynamic';
        if (dynMode === 'weredevs') result = await dynamicDecode(code);
        else                        result = await tryDynamicExecution(code);
        break;
      }
      case 'auto':
      default:                       result = await autoDeobfuscate(code);              break;
    }
  } catch (err) {
    // 未捕捉例外をサーバークラッシュさせずJSONで返す
    console.error('[/api/deobfuscate] 未捕捉エラー:', err);
    result = {
      success: false,
      error: '内部エラー: ' + (err && err.message ? err.message : String(err)),
      method: method || 'unknown',
    };
  }

  res.json(result);
});

// 後方互換
app.post('/deobfuscate', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(deobfuscateXOR(code));
});

// ════════════════════════════════════════════════════════
//  POST /api/decompile  — MoonSec V3 bytecodeデコンパイル
//
//  受け取り:
//    bytecode : Lua 5.1 バイトコード文字列
//    encoding : "binary"(デフォルト) | "base64"
//
//  パイプライン:
//    1. bytecodeを temp/bc_{id}.luac へ書き出す
//    2. lua moonsecv3decompiler.lua <input.luac> <output.lua> を実行
//    3. temp/dc_{id}.lua を読み込んで返す
//    4. 成功・失敗問わず一時ファイルを必ず削除 (finally)
// ════════════════════════════════════════════════════════
app.post('/api/decompile', async (req, res) => {
  const { bytecode, encoding } = req.body;
  if (!bytecode) return res.json({ success: false, error: 'bytecodeが提供されていません' });

  if (!fs.existsSync(DECOMPILER_LUA)) {
    return res.json({
      success: false,
      error: [
        'デコンパイラスクリプトが見つかりません。',
        `期待パス: ${DECOMPILER_LUA}`,
        'moonsecv3decompiler.lua をプロジェクトルートに配置してください。',
      ].join('\n'),
    });
  }

  res.json(await runDecompilePipeline(bytecode, encoding || 'binary'));
});

// ────────────────────────────────────────────────────────────────────────
//  runDecompilePipeline
// ────────────────────────────────────────────────────────────────────────
async function runDecompilePipeline(bytecode, encoding) {
  const id         = makeTempId();
  const inputFile  = path.join(tempDir, `bc_${id}.luac`);
  const outputFile = path.join(tempDir, `dc_${id}.lua`);

  try {
    // Step 1: bytecodeを一時ファイルへ書き出す
    if (encoding === 'base64') {
      fs.writeFileSync(inputFile, Buffer.from(bytecode, 'base64'));
    } else {
      // binary: バイナリ文字列をそのまま書き出す
      fs.writeFileSync(inputFile, bytecode, 'binary');
    }

    // Step 2-3: Luaプロセス実行 → 出力ファイル読み込み
    return await executeLuaDecompiler(inputFile, outputFile);

  } catch (err) {
    return { success: false, error: `パイプラインエラー: ${err.message}` };
  } finally {
    // Step 4: 成功・失敗問わず必ず削除
    safeUnlink(inputFile);
    safeUnlink(outputFile);
  }
}

// ────────────────────────────────────────────────────────────────────────
//  executeLuaDecompiler
//  lua "moonsecv3decompiler.lua" "input.luac" "output.lua"
// ────────────────────────────────────────────────────────────────────────
function executeLuaDecompiler(inputFile, outputFile) {
  const luaBin = checkLuaAvailable();
  if (!luaBin) return Promise.resolve({ success: false, error: 'Luaがインストールされていません' });

  return new Promise((resolve) => {
    // パスにスペースが含まれる場合に備えクォートで囲む
    const cmd = `${luaBin} "${DECOMPILER_LUA}" "${inputFile}" "${outputFile}"`;

    exec(cmd, {
      timeout:   30000,               // 30秒タイムアウト
      maxBuffer: 10 * 1024 * 1024,    // 10MB
      env: { PATH: process.env.PATH },
    }, (error, stdout, stderr) => {

      // 出力ファイルが存在すれば読み込む
      let outputContent = null;
      if (fs.existsSync(outputFile)) {
        try { outputContent = fs.readFileSync(outputFile, 'utf8'); } catch (_) {}
      }

      // コンテンツがあれば成功
      if (outputContent && outputContent.trim().length > 0) {
        return resolve({ success: true, result: outputContent, stdout: stdout || '' });
      }

      // 失敗: タイムアウト / stderr を返す
      if (error) {
        const errMsg = error.killed
          ? 'タイムアウト (30秒) — bytecodeが大きすぎるか無限ループの可能性があります'
          : (stderr ? stderr.trim() : error.message);
        return resolve({ success: false, error: `デコンパイル失敗: ${errMsg}`, stdout: stdout || '' });
      }

      // プロセス正常終了でも出力が空
      resolve({
        success: false,
        error:   'デコンパイル結果が空です。bytecodeが正しいLua 5.1形式か確認してください。',
        stdout:  stdout || '',
      });
    });
  });
}

// ════════════════════════════════════════════════════════
//  POST /api/obfuscate  — Prometheus 難読化
// ════════════════════════════════════════════════════════
app.post('/api/obfuscate', async (req, res) => {
  const { code, preset, steps } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(await obfuscateWithPrometheus(code, { preset, steps }));
});

// ════════════════════════════════════════════════════════
//  POST /api/vm-obfuscate  — カスタムVM難読化
// ════════════════════════════════════════════════════════
app.post('/api/vm-obfuscate', async (req, res) => {
  const { code, seed } = req.body;
  if (!code) return res.json({ success: false, error: 'コードが提供されていません' });
  res.json(await obfuscateWithCustomVM(code, { seed }));
});

// ════════════════════════════════════════════════════════
//  dynamicDecode
// ════════════════════════════════════════════════════════
async function dynamicDecode(code) {
  const luaBin = checkLuaAvailable();
  if (!luaBin) return { success: false, error: 'Luaがインストールされていません', method: 'dynamic_decode' };

  // ── Weredevs判定 ──────────────────────────────────────────────────────
  // sandboxFilter / safeEnvPreamble の適用可否をここで決める。
  // Weredevs VM は getfenv/setfenv を初期化に使うため、
  // safeEnvPreamble を適用するとVMが壊れる。
  const weredevMode = isWeredevWrapper(code);

  // ── sandboxFilter ──────────────────────────────────────────────────────
  // Weredevsモード: スキップ（getfenv/setfenv/loadstringを削除しない）
  // 通常モード    : 適用（危険な関数を除去）
  let codeToRun;
  if (weredevMode) {
    codeToRun = code;
  } else {
    const filtered = sandboxFilter(code);
    if (!filtered.safe) return { success: false, error: filtered.reason, method: 'dynamic_decode' };
    if (filtered.removed.length > 0) console.log('[DynDec] 危険関数除去:', filtered.removed.join(', '));
    codeToRun = filtered.code;
  }

  // セッション開始
  const sid = beginVmSession('dynamic_decode');

  // ── preamble ──────────────────────────────────────────────────────────
  // Weredevsモード: hookLoadstringCode + vmHookBootstrap のみ
  //                 （safeEnvPreamble は getfenv/setfenv を変更するためスキップ）
  // 通常モード    : safeEnvPreamble + hookLoadstringCode + vmHookBootstrap
  const preamble = weredevMode
    ? hookLoadstringCode + '\n' + vmHookBootstrap
    : safeEnvPreamble + '\n' + hookLoadstringCode + '\n' + vmHookBootstrap;

  let vmHookInjected = false, bytecodeCandidates = [];

  const vmInfoPre = vmDetector(codeToRun);

  // Weredevs モードでは while true do の有無に関係なく必ず injectVmHook を実行する。
  // それ以外の VM 系は従来通り while true do / repeat until がある場合のみ注入する。
  if (weredevMode) {
    const hookResult = injectVmHook(codeToRun, vmInfoPre);
    codeToRun = hookResult.code;
    vmHookInjected = hookResult.injected;
  } else if (vmInfoPre.isVm || vmInfoPre.isWereDev || vmInfoPre.isMoonSec || vmInfoPre.isLuraph) {
    const hasVmLoop = /while\s+true\s+do|repeat\s+until/.test(codeToRun);
    if (hasVmLoop) {
      const hookResult = injectVmHook(codeToRun, vmInfoPre);
      codeToRun = hookResult.code;
      vmHookInjected = hookResult.injected;
    }
  }

  if (vmInfoPre.isVm || vmInfoPre.isWereDev || vmInfoPre.isMoonSec || vmInfoPre.isLuraph || weredevMode) {
    const dumpResult = dumpBytecodeTables(codeToRun);
    codeToRun = dumpResult.code;
    bytecodeCandidates = dumpResult.candidates;
  }

  // ── 先頭の --[[ ... ]] ヘッダーコメントを削除 ────────────────────────
  codeToRun = codeToRun.replace(/^--\[\[[\s\S]*?\]\]\s*/, '');

  const vmInfo = vmDetector(codeToRun);
  const _vmDumpFooter = (typeof vmDumpFooter === 'string') ? vmDumpFooter : '';
  const fullCode = preamble + '\n' + codeToRun + '\n' + _vmDumpFooter;
  const safeFullCode = fullCode;
  const tempFile = path.join(tempDir, `dyndec_${makeTempId()}.lua`);

  // ── wrapper ───────────────────────────────────────────────────────────
  // Weredevsモード: getfenv ブロックを含まない（VM初期化を保護）
  //                 + Roblox仮想環境をグローバルに注入
  // 通常モード    : getfenv ブロックを含む
  const normalEnvBlock  = `
pcall(function()
  if getfenv then
    local env=getfenv()
    env.saveinstance=nil; env.dumpstring=nil; env.save_instance=nil
  end
end)
`;

  // ── Roblox仮想環境ブロック (engine.lua のメタテーブルロジックを移植) ──────
  // engine.lua の runner:wrap / runner:rbx_api / runner:vec3 に相当する
  // グローバルスタブを標準 Lua 5.1 環境に注入する。
  // Weredevs VM は getfenv/setfenv でグローバル環境を参照するため、
  // _G に直接書き込むことで確実にアクセスさせる。
  const rbxEnvBlock = `
-- ══ Roblox仮想環境 (engine.lua 移植) ══

-- ── 汎用スタブオブジェクト生成 ────────────────────────────────────────
-- engine.lua の runner:wrap に相当。
-- 存在しないキーへのアクセスを再帰的にスタブで返し、
-- 呼び出しもノーオプで受け入れる。
local function __rbx_wrap(name, props)
  local raw = props or {}
  local mt  = {}
  mt.__index = function(t, k)
    if raw[k] ~= nil then return raw[k] end
    -- 新しいスタブを生成して返す（engine.lua の self:wrap(k, {}) 相当）
    local child = __rbx_wrap(name .. "." .. tostring(k), {})
    raw[k] = child
    return child
  end
  mt.__newindex = function(t, k, v)
    rawset(raw, k, v)
  end
  mt.__call = function(t, ...)
    return __rbx_wrap(name .. "()", {})
  end
  mt.__tostring = function()
    return "<RBX:" .. name .. ">"
  end
  mt.__concat = function(a, b)
    return tostring(a) .. tostring(b)
  end
  mt.__len = function() return 0 end
  mt.__eq  = function() return false end
  mt.__lt  = function() return false end
  mt.__le  = function() return false end
  mt.__add = function(a,b) return 0 end
  mt.__sub = function(a,b) return 0 end
  mt.__mul = function(a,b) return 0 end
  mt.__div = function(a,b) return 0 end
  mt.__mod = function(a,b) return 0 end
  mt.__unm = function(a)   return 0 end
  return setmetatable({}, mt)
end

-- ── Vector3 (engine.lua の runner:vec3 相当) ──────────────────────────
local __Vector3 = {}
__Vector3.new = function(x, y, z)
  x = tonumber(x) or 0
  y = tonumber(y) or 0
  z = tonumber(z) or 0
  local v = {
    X = x, Y = y, Z = z,
    x = x, y = y, z = z,
    Magnitude = math.sqrt(x*x + y*y + z*z),
  }
  local vmt = {}
  vmt.__add      = function(a,b) return __Vector3.new((a.X or 0)+(b.X or 0),(a.Y or 0)+(b.Y or 0),(a.Z or 0)+(b.Z or 0)) end
  vmt.__sub      = function(a,b) return __Vector3.new((a.X or 0)-(b.X or 0),(a.Y or 0)-(b.Y or 0),(a.Z or 0)-(b.Z or 0)) end
  vmt.__mul      = function(a,b) if type(b)=="number" then return __Vector3.new((a.X or 0)*b,(a.Y or 0)*b,(a.Z or 0)*b) else return __Vector3.new((a.X or 0)*(b.X or 0),(a.Y or 0)*(b.Y or 0),(a.Z or 0)*(b.Z or 0)) end end
  vmt.__tostring = function() return "("..tostring(x)..","..tostring(y)..","..tostring(z)..")" end
  vmt.__index    = function(t,k) return rawget(v,k) end
  return setmetatable(v, vmt)
end
__Vector3.zero = __Vector3.new(0,0,0)
__Vector3.one  = __Vector3.new(1,1,1)

-- ── CFrame ──────────────────────────────────────────────────────────
local __CFrame = {}
__CFrame.new = function(...)
  local cf = { Position = __Vector3.new(0,0,0) }
  setmetatable(cf, { __tostring=function() return "CFrame()" end, __mul=function(a,b) return b end })
  return cf
end
__CFrame.identity = __CFrame.new()

-- ── Color3 / BrickColor ──────────────────────────────────────────────
local __Color3 = {}
__Color3.new     = function(r,g,b) return {R=r or 0,G=g or 0,B=b or 0,r=r or 0,g=g or 0,b=b or 0} end
__Color3.fromRGB = function(r,g,b) return __Color3.new((r or 0)/255,(g or 0)/255,(b or 0)/255) end

local __BrickColor = {}
__BrickColor.new = function(n) return {Name=tostring(n), Number=0, Color=__Color3.new(0,0,0)} end

-- ── UDim2 / UDim ─────────────────────────────────────────────────────
local __UDim2 = {}
__UDim2.new = function(xs,xo,ys,yo) return {X={Scale=xs or 0,Offset=xo or 0},Y={Scale=ys or 0,Offset=yo or 0}} end
local __UDim = {}
__UDim.new  = function(s,o) return {Scale=s or 0,Offset=o or 0} end

-- ── Enum スタブ ───────────────────────────────────────────────────────
local __Enum = __rbx_wrap("Enum", {})

-- ── Instance.new (engine.lua の api.Instances.new 相当) ───────────────
local __Instance = {}
__Instance.new = function(cls, parent)
  local inst = __rbx_wrap(tostring(cls), {
    Name       = tostring(cls),
    ClassName  = tostring(cls),
    Parent     = parent,
    Archivable = true,
  })
  -- よく使われるプロパティを事前定義
  local defaults = {
    Part      = {Size=__Vector3.new(1,1,1), Position=__Vector3.new(0,0,0), CFrame=__CFrame.new(), Anchored=false, CanCollide=true},
    Script    = {Source="", Disabled=false},
    Humanoid  = {Health=100, MaxHealth=100, WalkSpeed=16, JumpPower=50},
    Frame     = {Size=__UDim2.new(0,100,0,100), Position=__UDim2.new(0,0,0,0), BackgroundColor3=__Color3.new(1,1,1)},
  }
  if defaults[cls] then
    for k,v in pairs(defaults[cls]) do inst[k]=v end
  end
  inst.Destroy       = function() end
  inst.Remove        = function() end
  inst.Clone         = function() return __Instance.new(cls) end
  inst.FindFirstChild= function(n) return nil end
  inst.WaitForChild  = function(n,t) return __rbx_wrap(n,{}) end
  inst.GetChildren   = function() return {} end
  inst.GetDescendants= function() return {} end
  inst.IsA           = function(s, c) return tostring(cls)==c end
  inst.GetService    = function(s, n) return __rbx_wrap(n,{}) end
  inst.ConnectEvent  = function() return {Disconnect=function()end} end
  return inst
end

-- ── game オブジェクト (engine.lua の runner:rbx_api 相当) ─────────────
local __game = __rbx_wrap("game", {
  Workspace         = __rbx_wrap("Workspace", {}),
  Players           = __rbx_wrap("Players", {LocalPlayer=__rbx_wrap("LocalPlayer",{Name="Player",UserId=1,Character=__rbx_wrap("Character",{})})}),
  Lighting          = __rbx_wrap("Lighting", {}),
  ReplicatedStorage = __rbx_wrap("ReplicatedStorage", {}),
  ServerStorage     = __rbx_wrap("ServerStorage", {}),
  StarterGui        = __rbx_wrap("StarterGui", {}),
  StarterPack       = __rbx_wrap("StarterPack", {}),
  Teams             = __rbx_wrap("Teams", {}),
  HttpService       = __rbx_wrap("HttpService", {JSONEncode=function(s,t) return "{}" end, JSONDecode=function(s,d) return {} end}),
})
__game.GetService  = function(self, n) return __rbx_wrap(n, {}) end
__game.WaitForChild= function(self, n) return __rbx_wrap(n, {}) end

-- ── task / wait スタブ ────────────────────────────────────────────────
local __task = {
  wait     = function(t) return t or 0 end,
  spawn    = function(f, ...) if type(f)=="function" then pcall(f,...) end end,
  delay    = function(t,f,...) end,
  defer    = function(f,...) end,
  cancel   = function() end,
}

-- ── RunService スタブ ─────────────────────────────────────────────────
local __RunService = __rbx_wrap("RunService", {
  IsServer  = function() return false end,
  IsClient  = function() return true  end,
  IsStudio  = function() return false end,
  RenderStepped = __rbx_wrap("RenderStepped",{Connect=function(s,f) return {Disconnect=function()end} end}),
  Heartbeat     = __rbx_wrap("Heartbeat",    {Connect=function(s,f) return {Disconnect=function()end} end}),
  Stepped       = __rbx_wrap("Stepped",      {Connect=function(s,f) return {Disconnect=function()end} end}),
})

-- ── _G に全スタブを注入 ───────────────────────────────────────────────
-- engine.lua の setmetatable(env, {__index=...}) 相当をグローバルへ直接適用する。
-- Weredevs VM は getfenv() でグローバル環境を取得して参照するため、
-- _G への直接書き込みが最も確実な方法。
rawset(_G, "game",          __game)
rawset(_G, "workspace",     __game.Workspace)
rawset(_G, "Workspace",     __game.Workspace)
rawset(_G, "script",        __rbx_wrap("script", {Name="Script", Parent=__game.Workspace}))
rawset(_G, "Vector3",       __Vector3)
rawset(_G, "CFrame",        __CFrame)
rawset(_G, "Color3",        __Color3)
rawset(_G, "BrickColor",    __BrickColor)
rawset(_G, "UDim2",         __UDim2)
rawset(_G, "UDim",          __UDim)
rawset(_G, "Enum",          __Enum)
rawset(_G, "Instance",      __Instance)
rawset(_G, "task",          __task)
rawset(_G, "wait",          function(t) return t or 0 end)
rawset(_G, "delay",         function(t,f) end)
rawset(_G, "spawn",         function(f,...) if type(f)=="function" then pcall(f,...) end end)
rawset(_G, "RunService",    __RunService)
rawset(_G, "tick",          os.clock)
rawset(_G, "time",          os.clock)
rawset(_G, "os",            os)
rawset(_G, "warn",          function(...) end)
rawset(_G, "error",         error)
rawset(_G, "assert",        assert)
rawset(_G, "pcall",         pcall)
rawset(_G, "xpcall",        xpcall)
rawset(_G, "select",        select)
rawset(_G, "ipairs",        ipairs)
rawset(_G, "pairs",         pairs)
rawset(_G, "next",          next)
rawset(_G, "type",          type)
rawset(_G, "tostring",      tostring)
rawset(_G, "tonumber",      tonumber)
rawset(_G, "rawget",        rawget)
rawset(_G, "rawset",        rawset)
rawset(_G, "rawequal",      rawequal)
rawset(_G, "rawlen",        rawlen or function(t) return #t end)
rawset(_G, "unpack",        unpack or table.unpack)
rawset(_G, "setmetatable",  setmetatable)
rawset(_G, "getmetatable",  getmetatable)
rawset(_G, "collectgarbage",function(...) return 0 end)
rawset(_G, "string",        string)
rawset(_G, "table",         table)
rawset(_G, "math",          math)
rawset(_G, "io",            io)
rawset(_G, "coroutine",     coroutine)
rawset(_G, "print",         print)
-- ══ Roblox仮想環境 END ══
`;

  const wrapper = `
-- ══ YAJU dynamicDecode v4 Wrapper ══
pcall(function()
  if debug then
    debug.sethook=function() end; debug.getinfo=nil
    debug.getlocal=nil; debug.setlocal=nil
    debug.getupvalue=nil; debug.setupvalue=nil
  end
end)
${weredevMode ? rbxEnvBlock : normalEnvBlock}
local __obf_code = [=[
${safeFullCode}
]=]

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
-- _G に直接書き込む
loadstring = __outer_hook
load       = __outer_hook
if rawset then
  pcall(function() rawset(_G, "loadstring", __outer_hook) end)
  pcall(function() rawset(_G, "load",       __outer_hook) end)
end
-- getfenv() 経由でも差し替える (Weredevs は getfenv で環境を取得するため必須)
if getfenv then
  pcall(function()
    local _genv = getfenv(0)
    if _genv then
      _genv.loadstring = __outer_hook
      _genv.load       = __outer_hook
    end
  end)
  pcall(function()
    local _genv = getfenv(1)
    if _genv then
      _genv.loadstring = __outer_hook
      _genv.load       = __outer_hook
    end
  end)
end

local __ok, __err = pcall(function()
  local chunk, err = __orig_ls_outer(__obf_code)
  if not chunk then error("parse error: " .. tostring(err)) end
  local r = chunk()
  if type(r) == "function" then
    -- Weredevs形式: return(function(...) ... end)(args)
    -- chunk()の戻り値がfunctionの場合、それ自体がVMなので実行する
    -- 実行前にもう一度loadstringフックを確実に差し替える
    if getfenv then
      pcall(function()
        local _env = getfenv(r)
        if _env then
          _env.loadstring = __outer_hook
          _env.load       = __outer_hook
        end
      end)
    end
    r()
  end
end)

if not __ok then
  io.write("\\n__EXEC_ERROR__:" .. tostring(__err) .. "\\n")
end
`;

  return new Promise(resolve => {
    const luaCode = wrapper;
    fs.writeFileSync(tempFile, luaCode, 'utf8');
    console.log('[DynDec] Lua実行開始 bin=' + luaBin + ' file=' + tempFile);
    console.log('[DynDec] wrapper先頭200:', luaCode.substring(0, 200));
    console.log('[DynDec] wrapper末尾200:', luaCode.substring(luaCode.length - 200));
    exec(`${luaBin} ${tempFile}`, { timeout: 30000, maxBuffer: 50 * 1024 * 1024 }, (error, stdout, stderr) => {
      // デバッグ中はファイルを残す
      // safeUnlink(tempFile);
      console.log('[DynDec] Lua終了 error=' + (error && error.message) + ' stdout_len=' + (stdout && stdout.length) + ' stderr=' + (stderr && stderr.substring(0, 200)));
      console.log('[DynDec] stdout全文:', JSON.stringify(stdout && stdout.substring(0, 500)));
      try {

      const decoded      = parseDecodedOutputs(stdout);
      const vmTrace      = parseVmLogs(stdout);
      const vmTraceNew   = parseVmTrace(stdout);
      const bTableLog    = parseBTableLog(stdout);
      const vTableLog    = parseVTableLog(stdout);
      const strLog       = parseStrLog(stdout);
      const strCharLog   = parseStrCharLog(stdout);
      const tConcatLog   = parseTConcatLog(stdout);
      const bytecodeDump = parseBytecodeDump(stdout);

      const traceEntries = vmTraceNew.found ? vmTraceNew.entries : [];
      const traceForAnalysis = vmTraceNew.found
        ? traceEntries.map(e => ({ ip: e.pc || 0, op: e.l, arg1: e.A, arg2: e.B, arg3: e.C }))
        : vmTrace;

      const wereDevDetected = checkWereDevDetected(traceForAnalysis) || isWeredevObfuscated(codeToRun);
      if (traceForAnalysis.length > 0) saveVmTrace(traceForAnalysis, Date.now());

      // ── VMhook ログを global.vmLogs に記録 ──────────────────────────
      if (traceForAnalysis.length > 0 || vmTraceNew.found || bTableLog.found || strLog.found) {
        pushVmLog({
          method:        'dynamic_decode',
          traceCount:    vmTraceNew.found ? vmTraceNew.count : vmTrace.length,
          bTableCount:   bTableLog.found  ? bTableLog.count  : 0,
          strLogCount:   strLog.found     ? strLog.count      : 0,
          wereDevDetected,
          vmHookInjected,
          // トレースは先頭 200 件だけ保持してメモリを節約
          traceEntries:  traceForAnalysis.slice(0, 200),
          strEntries:    strLog.found ? strLog.entries.slice(0, 100) : [],
          bTableEntries: bTableLog.found ? (bTableLog.instructions || []).slice(0, 100) : [],
          bytecodeDump:  bytecodeDump || {},
        });
      }

      const weredevResult = weredevAnalyze(
        codeToRun,
        traceEntries.length > 0 ? traceEntries : traceForAnalysis,
        bTableLog,
        strLog.found ? strLog.entries : [],
        { maxInstructions: 100000 }
      );

      const vmAnalysis = {
        vmTrace: traceForAnalysis, vmTraceRaw: vmTraceNew.found ? vmTraceNew : null,
        bTable: bTableLog.found ? bTableLog : null, vTable: vTableLog.found ? vTableLog : null,
        strLog: strLog.found ? strLog : null, strCharLog: strCharLog.found ? strCharLog : null,
        tConcatLog: tConcatLog.found ? tConcatLog : null,
        bytecodeDump, wereDevDetected, vmHookInjected, bytecodeCandidates, vmInfo,
        traceCount:  vmTraceNew.found ? vmTraceNew.count : vmTrace.length,
        bTableCount: bTableLog.found  ? bTableLog.count  : 0,
        strLogCount: strLog.found     ? strLog.count      : 0,
        weredev:     weredevResult,
      };

      if (wereDevDetected) {
        vmAnalysis.traceAnalysis = vmTraceAnalyzer(traceForAnalysis);
        const finalOpcodeMap = {
          map: weredevResult.remapped,
          opcodeExecutionMap: vmAnalysis.traceAnalysis.opcodeMap &&
                              vmAnalysis.traceAnalysis.opcodeMap.opcodeExecutionMap || {},
        };
        vmAnalysis.reconstruction = vmDecompiler(traceForAnalysis, bytecodeDump, finalOpcodeMap);
        if (weredevResult.decompiledCode && weredevResult.decompiledCode.length > 50)
          vmAnalysis.weredevDecompiled = weredevResult.decompiledCode;
      }

      if (decoded.best && decoded.best.length >= 10) {
        const finalResult = { success: true, result: decoded.best, allDecoded: decoded.all.map(d => d.code), decodedCount: decoded.all.length, method: 'dynamic_decode', vmAnalysis: (vmTrace.length > 0 || wereDevDetected) ? vmAnalysis : undefined, _sid: sid };
        endVmSession(sid, finalResult);
        return resolve(finalResult);
      }
      if (wereDevDetected && vmAnalysis.reconstruction && vmAnalysis.reconstruction.success) {
        const pseudoCode = vmAnalysis.reconstruction.pseudoCode || '';
        if (pseudoCode.length >= 10) {
          const finalResult = { success: true, result: pseudoCode, method: 'dynamic_decode_vm', vmAnalysis, WereDevVMDetected: true, _sid: sid };
          endVmSession(sid, finalResult);
          return resolve(finalResult);
        }
      }
      if (wereDevDetected && vmAnalysis.weredevDecompiled && vmAnalysis.weredevDecompiled.length >= 50) {
        const finalResult = { success: true, result: vmAnalysis.weredevDecompiled, method: 'weredev_decompile', vmAnalysis, WereDevVMDetected: true, _sid: sid };
        endVmSession(sid, finalResult);
        return resolve(finalResult);
      }

      let errMsg = '';
      if (stdout && stdout.indexOf('__EXEC_ERROR__:') !== -1) {
        const errStart = stdout.indexOf('__EXEC_ERROR__:') + '__EXEC_ERROR__:'.length;
        const errEnd   = stdout.indexOf('\n', errStart);
        errMsg = (errEnd !== -1 ? stdout.substring(errStart, errEnd) : stdout.substring(errStart)).substring(0, 300);
      } else if (stderr) {
        errMsg = stderr.substring(0, 300);
      }

      const failResult = { success: false, error: errMsg || 'loadstringが呼ばれませんでした', method: 'dynamic_decode', vmAnalysis: vmTrace.length > 0 ? vmAnalysis : undefined, _sid: sid };
      endVmSession(sid, failResult);
      resolve(failResult);

      } catch (cbErr) {
        const r = { success: false, error: 'dynamicDecode 内部エラー: ' + (cbErr && cbErr.message || String(cbErr)), method: 'dynamic_decode', _sid: sid };
        try { endVmSession(sid, r); } catch (_) {}
        resolve(r);
      }
    });
  });
}

// ────────────────────────────────────────────────────────────────────────
//  isWeredevWrapper
//  以下のいずれかに一致した場合に Weredevs と判定する純粋関数。
//    1. コード中に "wearedevs.net" が含まれる
//    2. 先頭コメント除去後の文字列が return\s*(\s*function\s*( で始まる
//       （空白・改行に依存しない正規表現）
//  dispatchDynamic と autoDeobfuscate の両方から参照する。
// ────────────────────────────────────────────────────────────────────────
function isWeredevWrapper(code) {
  if (!code || typeof code !== 'string') return false;
  // 条件1: wearedevs.net を含む
  if (code.includes('wearedevs.net')) return true;
  // 条件2: コード中に return(function( 形式が存在する（位置・コメント問わず）
  return /return\s*\(\s*function/.test(code);
}

// ════════════════════════════════════════════════════════
//  tryDynamicExecution
// ════════════════════════════════════════════════════════
async function tryDynamicExecution(code) {
  const luaBin = checkLuaAvailable();
  if (!luaBin) return { success: false, error: 'Luaがインストールされていません', method: 'dynamic' };

  const sid = beginVmSession('try_dynamic');
  const tempFile = path.join(tempDir, `obf_${makeTempId()}.lua`);

  // ── 先頭の --[[ ... ]] ヘッダーコメントを削除 ────────────────────────
  const safeCode = code.replace(/^--\[\[[\s\S]*?\]\]\s*/, '');

  const wrapper = `
-- ══ YAJU Deobfuscator - Dynamic Execution Wrapper ══
local __captures = {}
local __capture_count = 0
local __original_loadstring = loadstring or load
local __original_load = load or loadstring

pcall(function()
  if debug then
    debug.sethook = function() end; debug.getinfo = nil
    debug.getlocal = nil; debug.setlocal = nil
    debug.getupvalue = nil; debug.setupvalue = nil
  end
end)
pcall(function()
  if getfenv then
    local env = getfenv()
    env.saveinstance = nil; env.dumpstring = nil; env.save_instance = nil
  end
end)

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

local __obf_code = [=[
${safeCode}
]=]

local __ok, __err = pcall(function()
  local chunk, err = __original_loadstring(__obf_code)
  if not chunk then error("parse error: " .. tostring(err)) end
  chunk()
end)

if __capture_count > 0 then
  local best = __captures[1]
  for i = 2, __capture_count do
    if #__captures[i] > #best then best = __captures[i] end
  end
  io.write("__CAPTURED_START__")
  io.write(best)
  io.write("__CAPTURED_END__")
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
      safeUnlink(tempFile);

      if (stdout.includes('__CAPTURED_START__') && stdout.includes('__CAPTURED_END__')) {
        const start    = stdout.indexOf('__CAPTURED_START__') + '__CAPTURED_START__'.length;
        const end      = stdout.indexOf('__CAPTURED_END__');
        const captured = stdout.substring(start, end).trim();
        if (captured && captured.length > 5) {
          const diffRatio = Math.abs(captured.length - code.length) / Math.max(code.length, 1);
          if (diffRatio <= 0.05 && captured === code.trim()) {
            const r = { success: false, error: 'capturedが元コードと同一のため停止', method: 'dynamic', _sid: sid };
            endVmSession(sid, r); return resolve(r);
          }
          const layerMatch = stdout.match(/__LAYERS__:(\d+)/);
          const layers = layerMatch ? parseInt(layerMatch[1]) : 1;
          pushVmLog({ method: 'dynamic', success: true, layers, capturedLength: captured.length, _sid: sid });
          const r = { success: true, result: captured, layers, method: 'dynamic', _sid: sid };
          endVmSession(sid, r); return resolve(r);
        }
      }
      if (stdout.includes('__ERROR__:')) {
        const errMsg = (stdout.split('__ERROR__:')[1] || '').substring(0, 300);
        pushVmLog({ method: 'dynamic', success: false, error: errMsg, _sid: sid });
        const r = { success: false, error: 'Luaエラー: ' + errMsg, method: 'dynamic', _sid: sid };
        endVmSession(sid, r); return resolve(r);
      }
      if (error && stderr) {
        pushVmLog({ method: 'dynamic', success: false, error: stderr.substring(0, 300), _sid: sid });
        const r = { success: false, error: '実行エラー: ' + stderr.substring(0, 300), method: 'dynamic', _sid: sid };
        endVmSession(sid, r); return resolve(r);
      }

      pushVmLog({ method: 'dynamic', success: false, error: 'no_capture', _sid: sid });
      const r = { success: false, error: 'loadstring()が呼ばれませんでした（VM系難読化の可能性）', method: 'dynamic', _sid: sid };
      endVmSession(sid, r); resolve(r);
    });
  });
}

// ════════════════════════════════════════════════════════
//  autoDeobfuscate
// ════════════════════════════════════════════════════════
async function autoDeobfuscate(code) {
  const results = [];
  let current = code;
  try {
  const luaBin = checkLuaAvailable();

  if (luaBin) {
    // ── mode 決定 (ここ1箇所のみで Weredevs 検出を行う) ──────────────
    // 以降のループ内では weredevMode フラグを参照するだけで
    // isWeredevWrapper() を再呼び出ししない。
    const weredevMode = isWeredevWrapper(current);

    // ── 1回目の動的実行 ────────────────────────────────────────────────
    const dynRes = weredevMode
      ? await dynamicDecode(current)
      : await tryDynamicExecution(current);
    results.push({ step: '動的実行 (1回目)', ...dynRes });

    if (dynRes.success && dynRes.result) {
      current = dynRes.result;
      for (let round = 2; round <= 4; round++) {
        if (!/loadstring|load\s*\(|[A-Za-z0-9+/]{60,}={0,2}/.test(current)) break;
        // ループ内も同じ weredevMode フラグを使用（再判定しない）
        const dynRes2 = weredevMode
          ? await dynamicDecode(current)
          : await tryDynamicExecution(current);
        results.push({ step: `動的実行 (${round}回目)`, ...dynRes2 });
        if (dynRes2.success && dynRes2.result && dynRes2.result !== current) current = dynRes2.result;
        else break;
      }
    } else {
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
        if (res.success && res.result && res.result !== current) { current = res.result; staticChanged = true; }
      }
      if (staticChanged) {
        // 静的解析後も同じ weredevMode フラグを使用（再判定しない）
        const dynRes3 = weredevMode
          ? await dynamicDecode(current)
          : await tryDynamicExecution(current);
        results.push({ step: '動的実行 (静的解析後)', ...dynRes3 });
        if (dynRes3.success && dynRes3.result) current = dynRes3.result;
      }
    }
  } else {
    results.push({ step: '動的実行', success: false, error: 'Luaがインストールされていません', method: 'dynamic' });
    for (const step of [
      { name: 'SplitStrings',    fn: deobfuscateSplitStrings },
      { name: 'EncryptStrings',  fn: deobfuscateEncryptStrings },
      { name: 'EvalExpressions', fn: evaluateExpressions },
      { name: 'ConstantArray',   fn: deobfuscateConstantArray },
      { name: 'XOR',             fn: deobfuscateXOR },
      { name: 'Vmify',           fn: deobfuscateVmify },
    ]) {
      const res = step.fn(current);
      results.push({ step: step.name, ...res });
      if (res.success && res.result && res.result !== current) current = res.result;
    }
  }

  return { success: results.some(r => r.success), steps: results, finalCode: current };
  } catch (err) {
    console.error('[autoDeobfuscate] 未捕捉エラー:', err);
    return {
      success: false,
      error: 'autoDeobfuscate 内部エラー: ' + (err && err.message ? err.message : String(err)),
      steps: results,
      finalCode: current,
    };
  }
}

// ════════════════════════════════════════════════════════
//  obfuscateWithPrometheus
// ════════════════════════════════════════════════════════
function obfuscateWithPrometheus(code, options = {}) {
  return new Promise(resolve => {
    const luaBin = checkLua51Available();
    if (!luaBin) { resolve({ success: false, error: 'lua5.1またはLuaJITがインストールされていません' }); return; }

    const cliPath = fs.existsSync(path.join(__dirname, 'prometheus', 'cli.lua'))
      ? path.join(__dirname, 'prometheus', 'cli.lua')
      : path.join(__dirname, 'cli.lua');
    if (!fs.existsSync(cliPath)) { resolve({ success: false, error: 'Prometheusが見つかりません' }); return; }

    const tmpIn  = path.join(tempDir, `prom_in_${makeTempId()}.lua`);
    const tmpOut = path.join(tempDir, `prom_out_${makeTempId()}.lua`);
    fs.writeFileSync(tmpIn, code);

    const preset = options.preset || 'Medium';
    const cmd = `${luaBin} ${cliPath} --preset ${preset} ${tmpIn} --out ${tmpOut}`;
    console.log('[Prometheus] cmd:', cmd);
    console.log('[Prometheus] input preview:', JSON.stringify(code.substring(0, 120)));

    exec(cmd, { timeout: 30000, cwd: path.dirname(cliPath) }, (err, stdout, stderr) => {
      safeUnlink(tmpIn);
      const errText = (stderr || '').trim();
      const outText = (stdout || '').trim();
      console.log('[Prometheus] stdout:', outText.substring(0, 200));
      console.log('[Prometheus] stderr:', errText.substring(0, 200));
      try {
        if (err) { resolve({ success: false, error: 'Lua: ' + errText }); return; }
        if (!fs.existsSync(tmpOut)) { resolve({ success: false, error: 'Prometheusが出力ファイルを生成しませんでした。stderr: ' + errText }); return; }
        const result = fs.readFileSync(tmpOut, 'utf8');
        if (!result || result.trim().length === 0) { resolve({ success: false, error: 'Prometheusの出力が空でした' }); return; }
        resolve({ success: true, result, preset });
      } finally {
        safeUnlink(tmpOut);
      }
    });
  });
}

// ════════════════════════════════════════════════════════
//  obfuscateWithCustomVM
// ════════════════════════════════════════════════════════
function obfuscateWithCustomVM(code, options = {}) {
  return new Promise(resolve => {
    const luaBin = checkLuaAvailable();
    if (!luaBin) { resolve({ success: false, error: 'Luaがインストールされていません' }); return; }

    const vmScript = path.join(__dirname, 'vm_obfuscator.lua');
    if (!fs.existsSync(vmScript)) { resolve({ success: false, error: 'vm_obfuscator.luaが見つかりません' }); return; }

    const seed   = options.seed || (Math.floor(Math.random() * 900000) + 100000);
    const tmpIn  = path.join(tempDir, `vm_in_${makeTempId()}.lua`);
    const tmpOut = path.join(tempDir, `vm_out_${makeTempId()}.lua`);
    fs.writeFileSync(tmpIn, code, 'utf8');

    const cmd = `${luaBin} ${vmScript} ${tmpIn} --out ${tmpOut} --seed ${seed}`;
    console.log('[VM] cmd:', cmd);

    exec(cmd, { timeout: 30000, cwd: __dirname }, (err, stdout, stderr) => {
      safeUnlink(tmpIn);
      const outText = (stdout || '').trim();
      const errText = (stderr || '').trim();
      console.log('[VM] stdout:', outText.substring(0, 200));
      if (errText) console.log('[VM] stderr:', errText.substring(0, 200));

      if (err) { resolve({ success: false, error: 'VM難読化エラー: ' + (errText || err.message) }); return; }
      if (!outText.startsWith('OK:') && !fs.existsSync(tmpOut)) {
        resolve({ success: false, error: 'VM難読化失敗: ' + (errText || outText || '出力なし') }); return;
      }
      try {
        if (!fs.existsSync(tmpOut)) { resolve({ success: false, error: '出力ファイルが見つかりません' }); return; }
        const result = fs.readFileSync(tmpOut, 'utf8');
        if (!result || result.trim().length === 0) { resolve({ success: false, error: 'VM難読化の出力が空でした' }); return; }
        resolve({ success: true, result, seed, method: 'custom_vm' });
      } finally {
        safeUnlink(tmpOut);
      }
    });
  });
}

// ════════════════════════════════════════════════════════
//  buildInlineLogHtml — public/log.html が無い場合のフォールバック
//  同一オリジンの /vmhook-logs を fetch してリアルタイム表示する
// ════════════════════════════════════════════════════════
function buildInlineLogHtml() {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VMhook Log Viewer</title>
<style>
  /* ── design tokens ─────────────────────────────────────── */
  :root{
    --bg:#0d1117;--surface:#161b22;--border:#30363d;
    --accent:#58a6ff;--green:#3fb950;--yellow:#d29922;--red:#f85149;
    --text:#c9d1d9;--muted:#8b949e;
  }

  /* ── reset ─────────────────────────────────────────────── */
  *{box-sizing:border-box;margin:0;padding:0;}

  /* ── base ──────────────────────────────────────────────── */
  body{
    background:var(--bg);color:var(--text);
    font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;
    display:flex;flex-direction:column;height:100vh;overflow:hidden;
  }

  /* ── header ────────────────────────────────────────────── */
  header{
    background:var(--surface);border-bottom:1px solid var(--border);
    padding:8px 14px;
    display:flex;align-items:center;gap:10px;
    flex-wrap:wrap;          /* ← モバイルで折り返す */
    flex-shrink:0;
  }
  header h1{font-size:14px;font-weight:600;color:var(--accent);white-space:nowrap;}
  .badge{
    background:#21262d;border:1px solid var(--border);
    border-radius:12px;padding:2px 8px;font-size:10px;color:var(--muted);
    white-space:nowrap;
  }
  .badge.live{border-color:var(--green);color:var(--green);}

  /* ── header controls ───────────────────────────────────── */
  .controls{
    margin-left:auto;
    display:flex;gap:6px;align-items:center;
    flex-wrap:wrap;          /* ← ボタン群を折り返す */
  }
  button{
    background:#21262d;border:1px solid var(--border);
    color:var(--text);border-radius:6px;
    padding:4px 10px;cursor:pointer;font-size:11px;
    white-space:nowrap;
  }
  button:hover{background:#30363d;}
  button.danger{border-color:var(--red);color:var(--red);}
  select,input[type=text]{
    background:#21262d;border:1px solid var(--border);
    color:var(--text);border-radius:6px;
    padding:3px 7px;font-size:11px;
  }

  /* ── toolbar ───────────────────────────────────────────── */
  .toolbar{
    background:var(--surface);border-bottom:1px solid var(--border);
    padding:5px 14px;
    display:flex;gap:8px;align-items:center;
    flex-wrap:wrap;          /* ← 小画面で折り返す */
    flex-shrink:0;
  }
  .toolbar label{color:var(--muted);font-size:10px;white-space:nowrap;}
  .toolbar input[type=text]{width:110px;}
  .toolbar .refresh-label{margin-left:auto;font-size:10px;color:var(--muted);white-space:nowrap;}

  /* ── main layout ───────────────────────────────────────── */
  main{display:flex;flex:1;overflow:hidden;min-height:0;}

  /* sessions サイドパネル (デスクトップ: 左固定幅) */
  #sessions-panel{
    width:200px;border-right:1px solid var(--border);
    overflow-y:auto;flex-shrink:0;background:var(--surface);
  }
  #sessions-panel h2{
    font-size:10px;color:var(--muted);
    padding:7px 10px;border-bottom:1px solid var(--border);
    text-transform:uppercase;letter-spacing:.5px;
  }
  .session-item{
    padding:7px 10px;border-bottom:1px solid var(--border);
    cursor:pointer;transition:background .1s;
  }
  .session-item:hover{background:#21262d;}
  .session-item.active{background:#1f2937;border-left:2px solid var(--accent);}
  .session-item .sid{font-size:9px;color:var(--muted);font-family:monospace;}
  .session-item .slabel{font-size:11px;font-weight:500;}
  .session-item .smeta{font-size:9px;color:var(--muted);margin-top:2px;}

  /* log パネル */
  #log-panel{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0;}

  /* stats bar */
  #stats-bar{
    background:#21262d;border-bottom:1px solid var(--border);
    padding:3px 12px;font-size:10px;color:var(--muted);
    display:flex;gap:12px;flex-wrap:wrap;flex-shrink:0;
  }
  #stats-bar span{color:var(--text);}

  /* ── テーブルラッパー: overflow-x:auto で横スクロール対応 ── */
  #log-table-wrap{
    flex:1;
    overflow-x:auto;   /* ← 横スクロール */
    overflow-y:auto;
    -webkit-overflow-scrolling:touch;
  }

  table{
    width:100%;border-collapse:collapse;
    font-family:'Cascadia Code',monospace;font-size:11px;
    min-width:640px;  /* ← 最小幅を確保して横スクロール発動 */
  }
  thead th{
    background:var(--surface);border-bottom:1px solid var(--border);
    padding:4px 8px;text-align:left;color:var(--muted);
    font-size:10px;position:sticky;top:0;z-index:1;white-space:nowrap;
  }
  tbody tr{border-bottom:1px solid #21262d;}
  tbody tr:hover{background:#161b22;}
  td{padding:2px 8px;vertical-align:top;white-space:nowrap;}
  td.regs{
    white-space:pre-wrap;font-size:10px;color:var(--muted);
    max-width:260px;overflow:hidden;text-overflow:ellipsis;
  }

  /* opcode バッジ */
  .op-badge{
    display:inline-block;padding:1px 5px;
    border-radius:4px;font-size:10px;font-weight:600;
  }
  .cat-MOVE  {background:#1f3a5f;color:#79c0ff;}
  .cat-CALL  {background:#3a1f5f;color:#d2a8ff;}
  .cat-ARITH {background:#1a3a2a;color:#56d364;}
  .cat-CONST {background:#3a2a1a;color:#e3b341;}
  .cat-JUMP  {background:#3a1a1a;color:#ff7b72;}
  .cat-LOAD,
  .cat-STORE {background:#1a2f3a;color:#58a6ff;}
  .cat-RETURN{background:#2a1a3a;color:#a5a0ff;}
  .cat-LOOP  {background:#1a3a3a;color:#39d353;}
  .cat-UNKNOWN{background:#21262d;color:var(--muted);}
  .pc-num{color:var(--muted);}
  .reg-val{color:#56d364;}

  /* empty state */
  #empty-msg{text-align:center;padding:48px 20px;color:var(--muted);}
  #empty-msg .icon{font-size:28px;}
  #empty-msg p{margin-top:8px;font-size:11px;line-height:1.6;}
  #empty-msg code{
    background:#21262d;border-radius:4px;
    padding:1px 5px;font-size:10px;color:var(--accent);
  }

  /* ════════════════════════════════════════════════════════
     @media (max-width: 768px)  — 縦1カラム レスポンシブ
  ═════════════════════════════════════════════════════════ */
  @media (max-width: 768px) {
    /* フォント・パディング縮小 */
    body{font-size:11px;}

    /* header: 2行に折り返す, h1小さく */
    header{padding:6px 10px;gap:6px;}
    header h1{font-size:12px;}
    .badge{font-size:9px;padding:1px 6px;}
    .controls{margin-left:0;width:100%;justify-content:flex-start;}
    button{padding:3px 8px;font-size:10px;}

    /* toolbar: 全アイテムを折り返す */
    .toolbar{padding:4px 10px;gap:6px;}
    .toolbar input[type=text]{width:90px;}
    .toolbar .refresh-label{margin-left:0;width:100%;}

    /* main: 縦1カラム化 */
    main{flex-direction:column;}

    /* sessions-panel: 上部に横長で表示 */
    #sessions-panel{
      width:100%;
      height:auto;
      max-height:140px;      /* 折りたたみ高さ上限 */
      border-right:none;
      border-bottom:1px solid var(--border);
      overflow-x:auto;
      overflow-y:auto;
      display:flex;
      flex-direction:row;    /* セッションカードを横並び */
      flex-wrap:nowrap;
      -webkit-overflow-scrolling:touch;
    }
    #sessions-panel h2{
      writing-mode:vertical-rl;
      text-orientation:mixed;
      padding:8px 4px;
      white-space:nowrap;
      border-bottom:none;
      border-right:1px solid var(--border);
      flex-shrink:0;
    }
    #sessions-list{
      display:flex;flex-direction:row;flex-wrap:nowrap;
    }
    .session-item{
      min-width:130px;max-width:160px;
      border-bottom:none;border-right:1px solid var(--border);
      padding:6px 8px;
    }
    .session-item .sid{font-size:8px;}
    .session-item .slabel{font-size:10px;}
    .session-item .smeta{font-size:8px;}

    /* stats bar: 折り返し */
    #stats-bar{padding:3px 10px;gap:8px;font-size:9px;}

    /* テーブル: overflow-x scrollは継承 (640px min-width維持) */
    table{font-size:10px;}
    thead th{padding:3px 6px;font-size:9px;}
    td{padding:2px 6px;}
    td.regs{max-width:180px;font-size:9px;}
    .op-badge{font-size:9px;padding:1px 4px;}

    /* empty msg */
    #empty-msg{padding:32px 16px;}
    #empty-msg .icon{font-size:22px;}
    #empty-msg p{font-size:10px;}
  }
</style>
</head>
<body>
<header>
  <h1>⚡ VMhook Log Viewer</h1>
  <span class="badge live" id="live-badge">● LIVE</span>
  <span class="badge" id="total-badge">0 entries</span>
  <span class="badge" id="sess-badge">0 sessions</span>
  <div class="controls">
    <button onclick="clearLogs()" class="danger">🗑 Clear</button>
    <button onclick="togglePause()" id="pause-btn">⏸ Pause</button>
    <button onclick="exportJson()">⬇ Export JSON</button>
  </div>
</header>
<div class="toolbar">
  <label>Filter opcode:</label>
  <input type="text" id="filter-op" placeholder="CALL, MOVE, ..." oninput="applyFilter()">
  <label>Type:</label>
  <select id="filter-type" onchange="applyFilter()">
    <option value="all">All</option>
    <option value="opcode">Opcode only</option>
    <option value="summary">Session summary</option>
  </select>
  <label>Limit:</label>
  <select id="filter-limit" onchange="fetchLogs()">
    <option value="200">200</option>
    <option value="500">500</option>
    <option value="1000">1000</option>
    <option value="5000">5000</option>
  </select>
  <span class="refresh-label">Auto-refresh: <span id="next-tick">3s</span></span>
</div>
<main>
  <div id="sessions-panel">
    <h2>Sessions</h2>
    <div id="sessions-list"><div style="padding:10px;color:var(--muted);font-size:10px;">No sessions yet</div></div>
  </div>
  <div id="log-panel">
    <div id="stats-bar">
      <div>Total: <span id="s-total">0</span></div>
      <div>Shown: <span id="s-shown">0</span></div>
      <div>Sessions: <span id="s-sess">0</span></div>
      <div>Last PC: <span id="s-pc">—</span></div>
      <div>Last op: <span id="s-op">—</span></div>
    </div>
    <div id="log-table-wrap">
      <div id="empty-msg">
        <div class="icon">📭</div>
        <p>VMhook ログがまだありません。</p>
        <p>解読 API <code>/api/deobfuscate</code> を実行すると<br>opcode ログがここに表示されます。</p>
      </div>
      <table id="log-table" style="display:none">
        <thead>
          <tr>
            <th>#</th><th>PC</th><th>Op</th><th>opName</th>
            <th>A</th><th>B</th><th>C</th>
            <th>Registers (before)</th><th>Time</th>
          </tr>
        </thead>
        <tbody id="log-body"></tbody>
      </table>
    </div>
  </div>
</main>
<script>
const OPCODE_CATS = {
  MOVE:'MOVE',LOADK:'CONST',LOADBOOL:'CONST',LOADNIL:'CONST',
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
function getCat(name){return OPCODE_CATS[(name||'').replace(/_inferred|_heuristic/g,'')]||'UNKNOWN';}

let allLogs = [];
let paused  = false;
let activeSid = null;
let countdown = 3;

function fmtTime(ts){if(!ts)return'—';const d=new Date(ts);return d.toTimeString().slice(0,8)+'.'+String(d.getMilliseconds()).padStart(3,'0');}
function fmtRegs(regs){if(!regs||typeof regs!=='object')return'{}';const entries=Object.entries(regs).slice(0,8);if(entries.length===0)return'{}';return entries.map(([k,v])=>'v'+k+'='+JSON.stringify(v).slice(0,20)).join('  ');}

async function fetchSessions(){
  try{
    const r=await fetch('/vmhook-logs/sessions');
    const d=await r.json();
    if(!d.success)return;
    document.getElementById('sess-badge').textContent=d.count+' sessions';
    document.getElementById('s-sess').textContent=d.count;
    const list=document.getElementById('sessions-list');
    if(d.sessions.length===0){list.innerHTML='<div style="padding:12px;color:var(--muted);font-size:11px;">No sessions yet</div>';return;}
    list.innerHTML=d.sessions.slice(0,20).map(s=>\`
      <div class="session-item\${s.id===activeSid?' active':''}" onclick="selectSession('\${s.id}')">
        <div class="slabel">\${s.label||'unnamed'}\${s.success===false?'<span style="color:var(--red)"> ✗</span>':s.success===true?'<span style="color:var(--green)"> ✓</span>':''}</div>
        <div class="sid">\${s.id.slice(0,24)}</div>
        <div class="smeta">\${s.logCount} opcodes · \${s.method||''}\${s.durationMs!=null?' · '+s.durationMs+' ms':''}</div>
      </div>
    \`).join('');
  }catch(e){}
}

async function selectSession(sid){
  activeSid=sid;
  await fetchSessions();
  await fetchLogs();
}

async function fetchLogs(){
  if(paused)return;
  try{
    const limit=document.getElementById('filter-limit').value;
    const type =document.getElementById('filter-type').value;
    const filterOp=(document.getElementById('filter-op').value||'').trim();
    let url=\`/vmhook-logs?limit=\${limit}&type=\${type}\`;
    if(activeSid) url+=\`&sid=\${activeSid}\`;
    if(filterOp)  url+=\`&opcode=\${encodeURIComponent(filterOp)}\`;
    const r=await fetch(url);
    const d=await r.json();
    if(!d.success)return;
    allLogs=d.logs;
    document.getElementById('total-badge').textContent=d.total+' entries';
    document.getElementById('s-total').textContent=d.total;
    document.getElementById('s-shown').textContent=d.count;
    const last=d.logs[d.logs.length-1];
    if(last){
      document.getElementById('s-pc').textContent=last.pc!==undefined?last.pc:'—';
      document.getElementById('s-op').textContent=last.opName||last.opcode||'—';
    }
    renderTable(d.logs);
    await fetchSessions();
  }catch(e){console.warn('fetch error',e);}
}

function applyFilter(){fetchLogs();}

function renderTable(logs){
  const empty=document.getElementById('empty-msg');
  const table=document.getElementById('log-table');
  const tbody=document.getElementById('log-body');
  if(logs.length===0){empty.style.display='block';table.style.display='none';return;}
  empty.style.display='none';table.style.display='table';
  tbody.innerHTML=logs.map((e,i)=>{
    if(e._type==='session_summary'){
      return \`<tr style="background:#21262d"><td colspan="9" style="color:var(--muted);font-size:11px;padding:4px 10px">
        📋 Session summary — method:\${e.method||'?'} · traces:\${e.traceCount||0} · bTable:\${e.bTableCount||0} · str:\${e.strLogCount||0}\${e.durationMs!=null?' · <span style="color:var(--yellow)">'+e.durationMs+' ms</span>':''}
      </td></tr>\`;
    }
    const cat=getCat(e.opName);
    const regsStr=fmtRegs(e.registers);
    return \`<tr>
      <td class="pc-num" style="color:var(--muted)">\${i+1}</td>
      <td class="pc-num">\${e.pc!==undefined?e.pc:'—'}</td>
      <td><span class="op-badge cat-\${cat}">\${e.opcode!==undefined?e.opcode:'?'}</span></td>
      <td style="color:var(--accent);font-weight:500">\${e.opName||'?'}</td>
      <td>\${e.A!==undefined&&e.A!==null?e.A:'—'}</td>
      <td>\${e.B!==undefined&&e.B!==null?e.B:'—'}</td>
      <td>\${e.C!==undefined&&e.C!==null?e.C:'—'}</td>
      <td class="regs reg-val">\${regsStr}</td>
      <td class="pc-num">\${fmtTime(e._ts)}</td>
    </tr>\`;
  }).join('');
}

async function clearLogs(){
  if(!confirm('全ログをクリアしますか？'))return;
  await fetch('/vmhook-logs?clear=1');
  allLogs=[];activeSid=null;
  await fetchLogs();
}

function togglePause(){
  paused=!paused;
  document.getElementById('pause-btn').textContent=paused?'▶ Resume':'⏸ Pause';
  document.getElementById('live-badge').textContent=paused?'⏸ PAUSED':'● LIVE';
  document.getElementById('live-badge').style.borderColor=paused?'var(--yellow)':'var(--green)';
  document.getElementById('live-badge').style.color=paused?'var(--yellow)':'var(--green)';
}

function exportJson(){
  const blob=new Blob([JSON.stringify(allLogs,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='vmhook-logs-'+Date.now()+'.json';a.click();
}

// ── countdown tick ────────────────────────────────────────
setInterval(()=>{
  if(paused){document.getElementById('next-tick').textContent='paused';return;}
  countdown--;
  document.getElementById('next-tick').textContent=countdown+'s';
  if(countdown<=0){countdown=3;fetchLogs();}
},1000);

fetchLogs();
</script>
</body>
</html>`;
}

// ════════════════════════════════════════════════════════
//  定期クリーンアップ + サーバー起動
// ════════════════════════════════════════════════════════
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
  console.log(`   Lua:        ${checkLuaAvailable()        || 'NOT FOUND'}`);
  console.log(`   Prometheus: ${checkPrometheusAvailable() ? 'OK' : 'NOT FOUND (optional)'}`);
  console.log(`   Decompiler: ${fs.existsSync(DECOMPILER_LUA) ? 'OK' : 'NOT FOUND — moonsecv3decompiler.lua をルートに配置してください'}`);
  console.log(`   VMhook Log: http://localhost:${PORT}/log`);
  console.log(`   VMhook API: http://localhost:${PORT}/vmhook-logs`);
});
