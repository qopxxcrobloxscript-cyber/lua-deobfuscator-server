const express = require('express');
const cors    = require('cors');
const { exec, execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// グローバルエラーハンドラー
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, error: 'コードが大きすぎます（最大10MB）' });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, error: 'サーバー内部エラー' });
});

// temp ディレクトリ
const tempDir = path.join(__dirname, 'temp');
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir);

// ════════════════════════════════════════════════════════
//  Lua / Prometheus 確認
// ════════════════════════════════════════════════════════
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
app.get('/api/status', (req, res) => {
  res.json({
    status: 'ok',
    lua: checkLuaAvailable() || 'not installed',
    prometheus: checkPrometheusAvailable() ? 'available' : 'not found',
    deobfuscateMethods: ['auto','advanced_static','eval_expressions','split_strings','xor','constant_array','dynamic','vmify','char_decoder','xor_decoder','math_eval','constant_call','str_transform','dead_branch','junk_clean','vm_detect','vm_extract','base64_detect'],
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
    case 'vm_extract':      result = vmBytecodeExtractor(code);       break;
    case 'base64_detect':   result = base64Detector(code, new CapturePool()); break;
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

/**
 * #7: loaderPatternDetected — table.concat + string.char + loadstring が揃うか
 */
function loaderPatternDetected(code) {
  const hasTableConcat  = /table\.concat\s*\(/.test(code);
  const hasStringChar   = /string\.char\s*\(/.test(code);
  const hasLoadstring   = /\bloadstring\b|\bload\s*\(/.test(code);
  return hasTableConcat && hasStringChar && hasLoadstring;
}

/**
 * #9: safeEnv — os.exit / while true do を無力化するLuaヘッダー
 */
const safeEnvPreamble = `
-- ══ YAJU SafeEnv ══
-- os.exit を無効化
pcall(function() os.exit = function() end end)
-- 危険なグローバルを無効化
pcall(function()
  os.execute = function() return false end
  io.popen   = function() return nil end
end)
-- while true do の暴走防止: デバッグフックで命令数カウント
local __safe_ops = 0
local __safe_max = 500000
pcall(function()
  if debug and debug.sethook then
    debug.sethook(function()
      __safe_ops = __safe_ops + 1
      if __safe_ops > __safe_max then
        debug.sethook()
        error("__SAFE_TIMEOUT__: 命令数上限到達", 2)
      end
    end, "", 1000)
  end
end)
-- ══ SafeEnv End ══
`;

/**
 * #3: hookLoadstring — loadstring/load を __DECODED__ を printするhookに差し替え
 */
const hookLoadstringCode = `
-- ══ YAJU hookLoadstring ══
local __orig_ls = loadstring or load
local __orig_ld = load or loadstring
local __decoded_count = 0
local __decoded_best  = nil
local __decoded_best_len = 0

local function __hookLoadstring(code_str, ...)
  if type(code_str) == "string" and #code_str > 10 then
    __decoded_count = __decoded_count + 1
    -- #4: __DECODED__ を stdout に出力
    io.write("\\n__DECODED_START_" .. tostring(__decoded_count) .. "__\\n")
    io.write(code_str)
    io.write("\\n__DECODED_END_" .. tostring(__decoded_count) .. "__\\n")
    -- 最長のものを best として保持
    if #code_str > __decoded_best_len then
      __decoded_best     = code_str
      __decoded_best_len = #code_str
    end
  end
  return __orig_ls(code_str, ...)
end

_G.loadstring = __hookLoadstring
_G.load       = __hookLoadstring
if rawset then
  pcall(function() rawset(_G, "loadstring", __hookLoadstring) end)
  pcall(function() rawset(_G, "load",       __hookLoadstring) end)
end
-- ══ hookLoadstring End ══
`;

/**
 * #4: parseDecodedOutputs — stdout から __DECODED__ を抽出して返す
 * 複数存在する場合は全て返し、最も長いものを best とする
 */
function parseDecodedOutputs(stdout) {
  const results = [];
  // 各 __DECODED_START_N__ ... __DECODED_END_N__ を抽出
  const re = /__DECODED_START_(\d+)__\n([\s\S]*?)\n__DECODED_END_\1__/g;
  let m;
  while ((m = re.exec(stdout)) !== null) {
    const idx  = parseInt(m[1]);
    const code = m[2];
    if (code && code.length > 5) results.push({ idx, code });
  }
  // 最長を best に
  const best = results.sort((a, b) => b.code.length - a.code.length)[0] || null;
  return { all: results, best: best ? best.code : null };
}

/**
 * #2: dynamicDecode — pipeline最初に置く動的デコードパス
 * loadstring を hookして __DECODED__ をダンプ
 */
async function dynamicDecode(code) {
  const luaBin = checkLuaAvailable();
  if (!luaBin) return { success: false, error: 'Luaがインストールされていません', method: 'dynamic_decode' };

  const filtered = sandboxFilter(code);
  if (!filtered.safe) return { success: false, error: filtered.reason, method: 'dynamic_decode' };

  const safeCode = filtered.code.replace(/\]\]/g, '] ]');

  // #9: safeEnv + #3: hookLoadstring + VMフックBootstrap を先頭に注入
  const preamble = safeEnvPreamble + '\n' + hookLoadstringCode + '\n' + vmHookBootstrap;

  // #6: VM検出は dynamicDecode 内で行い、VMループがある場合のみ vmHookInject
  const vmInfo = vmDetector(filtered.code);
  let codeToRun = filtered.code;
  let vmHookInjected = false;
  let bytecodeCandidates = [];

  // #6: while true do VMloop が検出された場合のみ hook注入
  if (vmInfo.isVm || vmInfo.isWereDev) {
    const hasWhileTrue = /while\s+true\s+do/.test(codeToRun);
    if (hasWhileTrue) {
      const hookResult = injectVmHook(codeToRun);
      codeToRun = hookResult.code;
      vmHookInjected = hookResult.injected;
    }
    // bytecodeテーブルのダンプ注入
    const dumpResult = dumpBytecodeTables(codeToRun);
    codeToRun = dumpResult.code;
    bytecodeCandidates = dumpResult.candidates;
  }

  const fullCode = preamble + '\n' + codeToRun + '\n' + vmDumpFooter;
  const safeFullCode = fullCode.replace(/\]\]/g, '] ]');

  const tempFile = path.join(tempDir, `dyndec_${Date.now()}_${Math.random().toString(36).substring(7)}.lua`);

  const wrapper = `
-- ══════════════════════════════════════════════════════
--  YAJU dynamicDecode Wrapper  (hookLoadstring + safeEnv)
-- ══════════════════════════════════════════════════════

-- アンチダンプ・アンチデバッグを無効化
pcall(function()
  if debug then
    debug.sethook = function() end
    debug.getinfo = nil; debug.getlocal = nil
    debug.setlocal = nil; debug.getupvalue = nil; debug.setupvalue = nil
  end
end)
pcall(function()
  if getfenv then
    local env = getfenv()
    env.saveinstance = nil; env.dumpstring = nil; env.save_instance = nil
  end
end)

local __obf_code = [[
${safeFullCode}
]]

local __orig_ls_outer = loadstring or load
local __ok, __err = pcall(function()
  local chunk, err = __orig_ls_outer(__obf_code)
  if not chunk then error("parse error: " .. tostring(err)) end
  chunk()
end)

if not __ok then
  io.write("\\n__EXEC_ERROR__:" .. tostring(__err))
end
`;

  return new Promise(resolve => {
    fs.writeFileSync(tempFile, wrapper, 'utf8');
    exec(`${luaBin} ${tempFile}`, { timeout: 15000, maxBuffer: 5 * 1024 * 1024 }, (error, stdout, stderr) => {
      try { fs.unlinkSync(tempFile); } catch {}

      // #4: __DECODED__ 抽出
      const decoded = parseDecodedOutputs(stdout);

      // VM ログ抽出
      const vmTrace = parseVmLogs(stdout);
      const bytecodeDump = parseBytecodeDump(stdout);
      const wereDevDetected = checkWereDevDetected(vmTrace);
      const vmAnalysis = { vmTrace, bytecodeDump, wereDevDetected, vmHookInjected, bytecodeCandidates };

      if (wereDevDetected) {
        vmAnalysis.traceAnalysis   = vmTraceAnalyzer(vmTrace);
        vmAnalysis.reconstruction  = reconstructedLuaBuilder(vmTrace, bytecodeDump, vmAnalysis.traceAnalysis.opcodeMap);
      }

      // __DECODED__ が取れた場合
      if (decoded.best) {
        return resolve({
          success: true,
          result: decoded.best,
          allDecoded: decoded.all.map(d => d.code),
          decodedCount: decoded.all.length,
          method: 'dynamic_decode',
          vmAnalysis: vmTrace.length > 0 ? vmAnalysis : undefined,
        });
      }

      // VMトレース再構築が取れた場合
      if (wereDevDetected && vmAnalysis.reconstruction && vmAnalysis.reconstruction.success) {
        return resolve({
          success: true,
          result: vmAnalysis.reconstruction.pseudoCode,
          method: 'dynamic_decode_vm',
          vmAnalysis,
          WereDevVMDetected: true,
        });
      }

      const errMsg = stdout.includes('__EXEC_ERROR__:')
        ? stdout.split('__EXEC_ERROR__:')[1]?.substring(0, 300) || ''
        : (stderr || '').substring(0, 300);

      resolve({
        success: false,
        error: errMsg || 'loadstringが呼ばれませんでした',
        method: 'dynamic_decode',
        vmAnalysis: vmTrace.length > 0 ? vmAnalysis : undefined,
      });
    });
  });
}

// ════════════════════════════════════════════════════════════════════════
//  tryDynamicExecution — 後方互換ラッパー (dynamicDecode を呼ぶ)
// ════════════════════════════════════════════════════════════════════════
async function tryDynamicExecution(code) {
  return dynamicDecode(code);
}



// ════════════════════════════════════════════════════════════════════════
//  YAJU Deobfuscator Engine v3
//  全20項目実装版
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
//  #19  seenCodeCache  — SHA1ハッシュによる重複解析防止
// ────────────────────────────────────────────────────────────────────────
const _seenCodeCache = new Map(); // hash -> result
function cacheHash(code) {
  return require('crypto').createHash('sha1').update(code).digest('hex');
}
function cacheGet(code) { return _seenCodeCache.get(cacheHash(code)) || null; }
function cacheSet(code, result) {
  const h = cacheHash(code);
  if (_seenCodeCache.size > 500) {
    // LRU簡易: 古いエントリを半分削除
    const keys = [..._seenCodeCache.keys()].slice(0, 250);
    keys.forEach(k => _seenCodeCache.delete(k));
  }
  _seenCodeCache.set(h, result);
}

// ────────────────────────────────────────────────────────────────────────
//  #20  capturePool  — 解析途中の文字列・コードを蓄積して再利用
// ────────────────────────────────────────────────────────────────────────
class CapturePool {
  constructor() { this.entries = []; }
  add(code, source) {
    if (code && code.length > 5 && !this.entries.some(e => e.code === code))
      this.entries.push({ code, source, ts: Date.now() });
  }
  getLuaCandidates() {
    return this.entries
      .filter(e => scoreLuaCode(e.code) > 20)
      .sort((a, b) => scoreLuaCode(b.code) - scoreLuaCode(a.code));
  }
  getBest() {
    const cands = this.getLuaCandidates();
    return cands.length ? cands[0].code : null;
  }
}

// ────────────────────────────────────────────────────────────────────────
//  共通ユーティリティ  (v2から引継ぎ + 拡張)
// ────────────────────────────────────────────────────────────────────────
function scoreLuaCode(code) {
  if (!code || typeof code !== 'string') return 0;
  const keywords = ['local','function','end','if','then','else','return','for','do',
    'while','and','or','not','nil','true','false','print','table','string','math'];
  let score = 0;
  keywords.forEach(kw => {
    const m = code.match(new RegExp('\\b' + kw + '\\b', 'g'));
    if (m) score += m.length * 10;
  });
  let printable = 0;
  for (let i = 0; i < Math.min(code.length, 2000); i++) {
    const c = code.charCodeAt(i);
    if (c >= 32 && c <= 126) printable++;
  }
  score += (printable / Math.min(code.length, 2000)) * 100;
  return score;
}

function hashCode(str) {
  let h = 0;
  for (let i = 0; i < Math.min(str.length, 4096); i++)
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  return h.toString(16);
}

function parseLuaArrayElements(content) {
  const elements = [];
  let cur = '', depth = 0, inStr = false, strChar = '', i = 0;
  while (i < content.length) {
    const c = content[i];
    if (!inStr) {
      if (c === '"' || c === "'") { inStr = true; strChar = c; cur += c; }
      else if (c === '[' && content[i+1] === '[') {
        let end = content.indexOf(']]', i + 2);
        if (end === -1) end = content.length - 2;
        cur += content.substring(i, end + 2); i = end + 2; continue;
      }
      else if (c === '{') { depth++; cur += c; }
      else if (c === '}') { depth--; cur += c; }
      else if (c === ',' && depth === 0) { elements.push(cur.trim()); cur = ''; }
      else { cur += c; }
    } else {
      if (c === '\\') { cur += c + (content[i+1] || ''); i += 2; continue; }
      if (c === strChar) inStr = false;
      cur += c;
    }
    i++;
  }
  if (cur.trim()) elements.push(cur.trim());
  return elements;
}

function resolveLuaStringEscapes(str) {
  return str
    .replace(/\\n/g,'\n').replace(/\\t/g,'\t').replace(/\\r/g,'\r')
    .replace(/\\\\/g,'\\').replace(/\\"/g,'"').replace(/\\'/g,"'")
    .replace(/\\x([0-9a-fA-F]{2})/g,(_,h)=>String.fromCharCode(parseInt(h,16)))
    .replace(/\\(\d{1,3})/g,(_,d)=>String.fromCharCode(parseInt(d,10)));
}

function stripLuaString(tok) {
  tok = (tok||'').trim();
  if ((tok.startsWith('"')&&tok.endsWith('"'))||(tok.startsWith("'")&&tok.endsWith("'"))) {
    try { return resolveLuaStringEscapes(tok.slice(1,-1)); } catch { return null; }
  }
  if (tok.startsWith('[[')&&tok.endsWith(']]')) return tok.slice(2,-2);
  return null;
}

function splitByComma(src) {
  const parts=[]; let cur='',depth=0,inStr=false,strCh='';
  for (let i=0;i<src.length;i++) {
    const c=src[i];
    if (!inStr) {
      if (c==='"'||c==="'") { inStr=true; strCh=c; cur+=c; }
      else if (c==='('||c==='{'||c==='[') { depth++; cur+=c; }
      else if (c===')'||c==='}'||c===']') { depth--; cur+=c; }
      else if (c===','&&depth===0) { parts.push(cur.trim()); cur=''; }
      else cur+=c;
    } else {
      if (c==='\\') { cur+=c+(src[i+1]||''); i++; continue; }
      if (c===strCh) inStr=false;
      cur+=c;
    }
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

function splitByConcat(src) {
  const parts=[]; let cur='',depth=0,inStr=false,strCh=''; let i=0;
  while (i<src.length) {
    const c=src[i];
    if (!inStr) {
      if (c==='"'||c==="'") { inStr=true; strCh=c; cur+=c; i++; continue; }
      if (c==='['&&src[i+1]==='[') {
        let end=src.indexOf(']]',i+2); if (end===-1) end=src.length-2;
        cur+=src.slice(i,end+2); i=end+2; continue;
      }
      if (c==='('||c==='{'||c==='[') { depth++; cur+=c; i++; continue; }
      if (c===')'||c==='}'||c===']') { depth--; cur+=c; i++; continue; }
      if (depth===0&&c==='.'&&src[i+1]==='.') {
        parts.push(cur.trim()); cur=''; i+=2;
        if (src[i]==='.') i++;
        continue;
      }
    } else {
      if (c==='\\') { cur+=c+(src[i+1]||''); i+=2; continue; }
      if (c===strCh) inStr=false;
    }
    cur+=c; i++;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

// ────────────────────────────────────────────────────────────────────────
//  Lua数値式パーサー  (evalLuaNumExpr — v2から引継ぎ)
// ────────────────────────────────────────────────────────────────────────
function evalLuaNumExpr(expr) {
  const src=(expr||'').trim(); if (!src) return null;
  let pos=0;
  const peek=()=>pos<src.length?src[pos]:'';
  const consume=()=>pos<src.length?src[pos++]:'';
  const skipWs=()=>{ while(pos<src.length&&/\s/.test(src[pos]))pos++; };
  function parseExpr(){ return parseAddSub(); }
  function parseAddSub(){
    let l=parseMulDiv(); if(l===null)return null; skipWs();
    while(peek()==='+' || peek()==='-'){
      const op=consume(); skipWs(); const r=parseMulDiv(); if(r===null)return null;
      l=op==='+'?l+r:l-r; skipWs();
    }
    return l;
  }
  function parseMulDiv(){
    let l=parsePow(); if(l===null)return null; skipWs();
    while(peek()==='*'||peek()==='/'||peek()==='%'){
      const op=consume(); skipWs(); const r=parsePow(); if(r===null)return null;
      if(op==='*')l=l*r;
      else if(op==='/'){if(r===0)return null; l=Math.floor(l/r);}
      else{if(r===0)return null; l=((l%r)+r)%r;}
      skipWs();
    }
    return l;
  }
  function parsePow(){
    let b=parseUnary(); if(b===null)return null; skipWs();
    if(peek()==='^'){ consume(); skipWs(); const e=parseUnary(); if(e===null)return null; b=Math.pow(b,e); }
    return b;
  }
  function parseUnary(){
    skipWs();
    if(peek()==='-'){ consume(); skipWs(); const v=parseAtom(); return v===null?null:-v; }
    if(peek()==='+') consume();
    return parseAtom();
  }
  function parseAtom(){
    skipWs();
    if(peek()==='('){ consume(); const v=parseExpr(); skipWs(); if(peek()===')') consume(); return v; }
    if(src.startsWith('math.',pos)){
      pos+=5; let fname='';
      while(pos<src.length&&/[a-z]/.test(src[pos])) fname+=src[pos++];
      skipWs(); if(peek()!=='(') return null; consume();
      const args=[]; skipWs();
      while(peek()!==')'&&pos<src.length){ const a=parseExpr(); if(a===null)return null; args.push(a); skipWs(); if(peek()===','){consume();skipWs();} }
      if(peek()===')') consume();
      if(fname==='floor') return Math.floor(args[0]??0);
      if(fname==='ceil')  return Math.ceil(args[0]??0);
      if(fname==='abs')   return Math.abs(args[0]??0);
      if(fname==='max')   return args.length?Math.max(...args):null;
      if(fname==='min')   return args.length?Math.min(...args):null;
      if(fname==='sqrt')  return Math.sqrt(args[0]??0);
      return null;
    }
    if(src[pos]==='0'&&(src[pos+1]==='x'||src[pos+1]==='X')){
      pos+=2; let h='';
      while(pos<src.length&&/[0-9a-fA-F]/.test(src[pos])) h+=src[pos++];
      const n=parseInt(h,16); return isNaN(n)?null:n;
    }
    let numStr='';
    while(pos<src.length&&/[0-9.]/.test(src[pos])) numStr+=src[pos++];
    if(numStr===''||numStr==='.') return null;
    const n=parseFloat(numStr); return isNaN(n)?null:n;
  }
  try {
    const result=parseExpr(); skipWs();
    if(result===null||!isFinite(result)) return null;
    if(pos<src.length) return null;
    return result;
  } catch { return null; }
}
function evalSimpleExpr(expr) {
  const r=evalLuaNumExpr(expr); if(r===null)return null;
  return Number.isInteger(r)?r:Math.floor(r);
}

// ────────────────────────────────────────────────────────────────────────
//  SymbolicEnv  (v2から引継ぎ)
// ────────────────────────────────────────────────────────────────────────
class SymbolicEnv {
  constructor(parent=null){ this.vars=new Map(); this.parent=parent; }
  get(name){ if(this.vars.has(name))return this.vars.get(name); if(this.parent)return this.parent.get(name); return null; }
  set(name,entry){ this.vars.set(name,entry); }
  child(){ return new SymbolicEnv(this); }
}

function evalStringChar(argsStr,env) {
  const args=splitByComma(argsStr); const chars=[];
  for(const a of args){
    const val=evalExprWithEnv(a.trim(),env);
    if(val===null||typeof val!=='number') return null;
    const code=Math.round(val); if(code<0||code>255) return null;
    chars.push(String.fromCharCode(code));
  }
  return chars.join('');
}

function evalArithWithEnv(expr,env){
  if(!env) return evalLuaNumExpr(expr);
  let resolved=expr.replace(/\b([a-zA-Z_]\w*)\b/g,(m)=>{
    if(/^(math)$/.test(m)) return m;
    const entry=env?env.get(m):null;
    if(entry&&entry.type==='num') return String(entry.value);
    return m;
  });
  if(/[a-zA-Z_]/.test(resolved.replace(/math\./g,''))) return null;
  return evalLuaNumExpr(resolved);
}

function evalExprWithEnv(expr,env){
  if(!expr) return null; expr=expr.trim();
  const strVal=stripLuaString(expr); if(strVal!==null) return strVal;
  if(expr==='true') return 1; if(expr==='false'||expr==='nil') return 0;
  if(/^[\d\s\+\-\*\/\%\(\)\.\^x0-9a-fA-FxX]+$/.test(expr)||/^[\-\+]?\s*math\./.test(expr)){
    const n=evalLuaNumExpr(expr); if(n!==null) return n;
  }
  const scMatch=expr.match(/^string\.char\((.+)\)$/s);
  if(scMatch) return evalStringChar(scMatch[1],env);
  const tsMatch=expr.match(/^tostring\((.+)\)$/s);
  if(tsMatch){ const v=evalExprWithEnv(tsMatch[1],env); if(v!==null) return String(v); }
  const tnMatch=expr.match(/^tonumber\((.+?)(?:,\s*(\d+))?\)$/s);
  if(tnMatch){
    const v=evalExprWithEnv(tnMatch[1],env);
    if(typeof v==='string'){ const base=tnMatch[2]?parseInt(tnMatch[2]):10; const n=parseInt(v,base); if(!isNaN(n)) return n; }
    if(typeof v==='number') return v;
  }
  const repMatch=expr.match(/^string\.rep\((.+?),\s*(\d+)\)$/s);
  if(repMatch){ const s=evalExprWithEnv(repMatch[1],env); const n=parseInt(repMatch[2]); if(typeof s==='string'&&!isNaN(n)) return s.repeat(n); }
  const subMatch=expr.match(/^string\.sub\((.+?),\s*(-?\d+)(?:,\s*(-?\d+))?\)$/s);
  if(subMatch){
    const s=evalExprWithEnv(subMatch[1],env);
    if(typeof s==='string'){
      let i=parseInt(subMatch[2]),j=subMatch[3]!==undefined?parseInt(subMatch[3]):s.length;
      if(i<0) i=Math.max(0,s.length+i+1); if(j<0) j=s.length+j+1;
      return s.slice(i-1,j);
    }
  }
  const revMatch=expr.match(/^string\.reverse\((.+)\)$/s);
  if(revMatch){ const s=evalExprWithEnv(revMatch[1],env); if(typeof s==='string') return s.split('').reverse().join(''); }
  const byteMatch=expr.match(/^string\.byte\((.+?),\s*(\d+)(?:,\s*\d+)?\)$/s);
  if(byteMatch){ const s=evalExprWithEnv(byteMatch[1],env); const i=parseInt(byteMatch[2]); if(typeof s==='string'&&i>=1&&i<=s.length) return s.charCodeAt(i-1); }
  const tcMatch=expr.match(/^table\.concat\((\w+)(?:,\s*(.+?))?\)$/s);
  if(tcMatch&&env){
    const tbl=env.get(tcMatch[1]);
    if(tbl&&tbl.type==='table'&&Array.isArray(tbl.value)){
      const sep=tcMatch[2]?(evalExprWithEnv(tcMatch[2],env)??''):'';
      if(typeof sep==='string'){
        const parts=tbl.value.map(v=>typeof v==='string'?v:typeof v==='number'?String(v):null);
        if(parts.every(p=>p!==null)) return parts.join(sep);
      }
    }
  }
  const gfMatch=expr.match(/^(?:getfenv\(\)|_G)\s*\[\s*(.+?)\s*\]$/s);
  if(gfMatch){ const key=evalExprWithEnv(gfMatch[1],env); if(typeof key==='string') return key; }
  const rawgetMatch=expr.match(/^rawget\s*\(\s*(?:_G|getfenv\(\))\s*,\s*(.+?)\s*\)$/s);
  if(rawgetMatch){ const key=evalExprWithEnv(rawgetMatch[1],env); if(typeof key==='string') return key; }
  const concatParts=splitByConcat(expr);
  if(concatParts.length>1){
    const resolved=concatParts.map(p=>evalExprWithEnv(p.trim(),env));
    if(resolved.every(v=>v!==null)) return resolved.map(String).join('');
  }
  if(env&&/^\w+$/.test(expr)){ const entry=env.get(expr); if(entry&&(entry.type==='num'||entry.type==='str')) return entry.value; }
  const arrMatch=expr.match(/^(\w+)\[(.+)\]$/);
  if(arrMatch&&env){
    const tbl=env.get(arrMatch[1]);
    if(tbl&&tbl.type==='table'&&Array.isArray(tbl.value)){
      const idx=evalExprWithEnv(arrMatch[2],env);
      if(typeof idx==='number'){ const v=tbl.value[Math.round(idx)-1]; if(v!==undefined) return v; }
    }
  }
  const numResult=evalArithWithEnv(expr,env); if(numResult!==null) return numResult;
  return null;
}

// ════════════════════════════════════════════════════════════════════════
//  #1  autoDeobfuscate 処理順は後述 — まず全パスを実装
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
//  #2  evaluateExpressions  — Lua定数式を正規表現で検出して評価
// ────────────────────────────────────────────────────────────────────────
function evaluateExpressions(code) {
  let modified=code, found=false;
  let prev, iters=0;
  do {
    prev=modified;
    // 括弧内の純粋数値式（文字列外）
    modified=modified.replace(/\(([^()'"\n]{1,120})\)/g,(match,inner)=>{
      if(/["']/.test(inner)) return match;
      const v=evalLuaNumExpr(inner);
      if(v===null||!Number.isInteger(v)) return match;
      if(String(v)===inner.trim()) return match;
      found=true; return String(v);
    });
    // 代入右辺の裸の数値算術
    modified=modified.replace(/(=\s*)([0-9][0-9\s\+\-\*\/\%\^\(\)\.]*[0-9])/g,(match,eq,expr)=>{
      if(/[a-zA-Z]/.test(expr)) return match;
      const v=evalLuaNumExpr(expr);
      if(v===null||!Number.isInteger(v)) return match;
      if(String(v)===expr.trim()) return match;
      found=true; return eq+String(v);
    });
    // 配列インデックス内の式
    modified=modified.replace(/\[\s*([0-9][0-9\s\+\-\*\/\%\^\(\)\.]*)\s*\]/g,(match,expr)=>{
      const v=evalLuaNumExpr(expr); if(v===null||!Number.isInteger(v)) return match;
      if(String(v)===expr.trim()) return match;
      found=true; return `[${v}]`;
    });
  } while(modified!==prev&&++iters<30);
  if(!found) return { success:false, error:'評価できる定数式がありませんでした', method:'eval_expressions' };
  return { success:true, result:modified, method:'eval_expressions' };
}

// ────────────────────────────────────────────────────────────────────────
//  #3  splitStrings  — 連続文字列連結を1つにまとめる
// ────────────────────────────────────────────────────────────────────────
function deobfuscateSplitStrings(code) {
  let modified=code, found=false;
  let prev, iters=0;
  do {
    prev=modified;
    // 任意の組み合わせ
    modified=modified.replace(/"((?:[^"\\]|\\.)*)"\s*\.\.\s*"((?:[^"\\]|\\.]*)*)"/g,(_,a,b)=>{ found=true; return `"${a}${b}"`; });
    modified=modified.replace(/'((?:[^'\\]|\\.)*)'\s*\.\.\s*'((?:[^'\\]|\\.]*)*)'/g,(_,a,b)=>{ found=true; return `'${a}${b}'`; });
    modified=modified.replace(/"((?:[^"\\]|\\.)*)"\s*\.\.\s*'((?:[^'\\]|\\.]*)*)'/g,(_,a,b)=>{ found=true; return `"${a}${b}"`; });
    modified=modified.replace(/'((?:[^'\\]|\\.)*)'\s*\.\.\s*"((?:[^"\\]|\\.]*)*)"/g,(_,a,b)=>{ found=true; return `"${a}${b}"`; });
  } while(modified!==prev&&++iters<80);
  if(!found) return { success:false, error:'SplitStringsパターンが見つかりません', method:'split_strings' };
  return { success:true, result:modified, method:'split_strings' };
}

// ────────────────────────────────────────────────────────────────────────
//  #4  charDecoder  — string.char(n,n,...) を文字列へ復元
// ────────────────────────────────────────────────────────────────────────
function charDecoder(code, env) {
  env=env||new SymbolicEnv();
  let modified=code, found=false;
  // まず定数式を畳み込む
  modified=modified.replace(/string\.char\(([^)]+)\)/g,(match,argsStr)=>{
    const val=evalStringChar(argsStr,env); if(val===null) return match;
    const esc=val.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\n/g,'\\n').replace(/\r/g,'\\r').replace(/\0/g,'\\0');
    found=true; return `"${esc}"`;
  });
  if(!found) return { success:false, error:'string.charパターンが見つかりません', method:'char_decoder' };
  return { success:true, result:modified, method:'char_decoder' };
}

// ────────────────────────────────────────────────────────────────────────
//  #5  xorDecoder  — string.char(x^y) や bit.bxor(x,y) パターンのXOR復号
// ────────────────────────────────────────────────────────────────────────
function xorDecoder(code) {
  let modified=code, found=false;

  // string.char(a ~ b) — Lua5.3以降の ~ 演算子
  modified=modified.replace(/string\.char\((\d+)\s*~\s*(\d+)\)/g,(_,a,b)=>{
    const v=parseInt(a)^parseInt(b); found=true;
    return `string.char(${v})`;
  });

  // bit.bxor(a, b) パターン
  modified=modified.replace(/bit\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g,(_,a,b)=>{
    found=true; return String(parseInt(a)^parseInt(b));
  });

  // string.char(x ^ y) — Lua5.3 XOR
  modified=modified.replace(/\b(\d+)\s*\^\s*(\d+)\b/g,(match,a,b)=>{
    // ^ がべき乗ではなくXORとして使われているかを判断
    // 両方255以下なら XOR として扱う（べき乗なら結果が大きすぎる）
    const ia=parseInt(a),ib=parseInt(b);
    if(ia<=255&&ib<=255){ found=true; return String(ia^ib); }
    return match;
  });

  // XOR配列ブルートフォース (既存コード)
  const xorRes=deobfuscateXOR(code);
  if(xorRes.success) return { ...xorRes, method:'xor_decoder' };

  if(!found) return { success:false, error:'XORパターンが見つかりません', method:'xor_decoder' };
  return { success:true, result:modified, method:'xor_decoder' };
}

// XOR配列ブルートフォース（後方互換）
function deobfuscateXOR(code) {
  function xorByte(b,k){ let r=0; for(let i=0;i<8;i++){const a=(b>>i)&1,bk=(k>>i)&1; if(a!==bk)r|=(1<<i);} return r; }
  const patterns=[/local\s+\w+\s*=\s*\{([0-9,\s]+)\}/g,/\{([0-9,\s]+)\}/g];
  let encryptedArrays=[];
  for(const pattern of patterns){
    let match; const p=new RegExp(pattern.source,pattern.flags);
    while((match=p.exec(code))!==null){
      const nums=match[1].split(',').map(n=>parseInt(n.trim())).filter(n=>!isNaN(n));
      if(nums.length>3) encryptedArrays.push(nums);
    }
    if(encryptedArrays.length>0) break;
  }
  if(encryptedArrays.length===0) return { success:false, error:'暗号化配列が見つかりません', method:'xor' };
  let bestResult=null,bestScore=-1,bestKey=-1;
  for(const arr of encryptedArrays){
    for(let key=0;key<=255;key++){
      const str=arr.map(b=>String.fromCharCode(xorByte(b,key))).join('');
      const score=scoreLuaCode(str);
      if(score>bestScore){ bestScore=score; bestResult=str; bestKey=key; }
    }
  }
  if(bestScore<10) return { success:false, error:'有効なLuaコードが見つかりませんでした', method:'xor' };
  return { success:true, result:bestResult, key:bestKey, score:bestScore, method:'xor' };
}

// ────────────────────────────────────────────────────────────────────────
//  #6  constantArrayResolver  — local t={...} の t[i] を直接値へ置換
// ────────────────────────────────────────────────────────────────────────
function constantArrayResolver(code, env) {
  env=env||new SymbolicEnv();
  let modified=code, found=false;
  let passCount=0;
  while(passCount++<12){
    let changed=false;
    const arrayPattern=/local\s+(\w+)\s*=\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}/g;
    let match; const snapshot=modified;
    while((match=arrayPattern.exec(snapshot))!==null){
      const varName=match[1],content=match[2];
      const elements=parseLuaArrayElements(content);
      if(elements.length<1) continue;
      const values=elements.map(e=>{
        const n=evalLuaNumExpr(e.trim()); if(n!==null) return n;
        const s=stripLuaString(e.trim()); if(s!==null) return s;
        return null;
      });
      if(values.some(v=>v===null)) continue;
      env.set(varName,{type:'table',value:values});
      const esc=varName.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
      const indexRe=new RegExp(esc+'\\[([^\\]]+)\\]','g');
      modified=modified.replace(indexRe,(fullMatch,indexExpr)=>{
        const idx=evalExprWithEnv(indexExpr,env);
        if(idx===null||typeof idx!=='number') return fullMatch;
        const rounded=Math.round(idx);
        if(rounded<1||rounded>values.length) return fullMatch;
        found=true; changed=true;
        const v=values[rounded-1];
        if(typeof v==='string') return `"${v.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`;
        return String(v);
      });
    }
    if(!changed) break;
  }
  if(!found) return { success:false, error:'ConstantArrayパターンが見つかりません', method:'constant_array' };
  return { success:true, result:modified, method:'constant_array' };
}
// 後方互換
function deobfuscateConstantArray(code){ return constantArrayResolver(code); }

// ────────────────────────────────────────────────────────────────────────
//  #7  constantCallEvaluator  — tonumber/tostring の定数呼び出しを変換
// ────────────────────────────────────────────────────────────────────────
function constantCallEvaluator(code) {
  let modified=code, found=false;
  // tonumber("123") -> 123, tonumber("0xff") -> 255
  modified=modified.replace(/\btonumber\s*\(\s*"([^"]+)"\s*(?:,\s*(\d+))?\s*\)/g,(_,s,base)=>{
    const n=parseInt(s,base?parseInt(base):10);
    if(isNaN(n)) return _;
    found=true; return String(n);
  });
  modified=modified.replace(/\btonumber\s*\(\s*'([^']+)'\s*(?:,\s*(\d+))?\s*\)/g,(_,s,base)=>{
    const n=parseInt(s,base?parseInt(base):10);
    if(isNaN(n)) return _;
    found=true; return String(n);
  });
  // tostring(123) -> "123"
  modified=modified.replace(/\btostring\s*\(\s*(-?\d+(?:\.\d+)?)\s*\)/g,(_,n)=>{
    found=true; return `"${n}"`;
  });
  if(!found) return { success:false, error:'tonumber/tostringの定数呼び出しが見つかりません', method:'constant_call' };
  return { success:true, result:modified, method:'constant_call' };
}

// ────────────────────────────────────────────────────────────────────────
//  #8  mathEvaluator  — math.* の引数が定数なら結果に置換
// ────────────────────────────────────────────────────────────────────────
function mathEvaluator(code) {
  let modified=code, found=false;
  const fns=['floor','ceil','abs','sqrt','max','min'];
  for(const fn of fns){
    const re=new RegExp(`math\\.${fn}\\s*\\(([^)]+)\\)`,'g');
    modified=modified.replace(re,(match,args)=>{
      const argList=splitByComma(args).map(a=>evalLuaNumExpr(a.trim()));
      if(argList.some(v=>v===null)) return match;
      let result;
      if(fn==='floor') result=Math.floor(argList[0]);
      else if(fn==='ceil') result=Math.ceil(argList[0]);
      else if(fn==='abs') result=Math.abs(argList[0]);
      else if(fn==='sqrt') result=Math.sqrt(argList[0]);
      else if(fn==='max') result=Math.max(...argList);
      else if(fn==='min') result=Math.min(...argList);
      if(result===undefined||!isFinite(result)) return match;
      found=true;
      return Number.isInteger(result)?String(result):result.toFixed(6);
    });
  }
  if(!found) return { success:false, error:'math.*の定数呼び出しが見つかりません', method:'math_eval' };
  return { success:true, result:modified, method:'math_eval' };
}

// ────────────────────────────────────────────────────────────────────────
//  #9  deadBranchRemover  — if true/false の不要分岐を削除
// ────────────────────────────────────────────────────────────────────────
function deadBranchRemover(code) {
  let modified=code, found=false;
  // if true then ... end  → 中身だけ残す
  modified=modified.replace(/\bif\s+true\s+then\s+([\s\S]*?)\s*end\b/g,(_,body)=>{ found=true; return body.trim(); });
  // if false then ... end  → 完全削除
  modified=modified.replace(/\bif\s+false\s+then\s+[\s\S]*?\s*end\b/g,()=>{ found=true; return ''; });
  // if true then ... else ... end → then節だけ残す
  modified=modified.replace(/\bif\s+true\s+then\s+([\s\S]*?)\s*else\s+[\s\S]*?\s*end\b/g,(_,thenPart)=>{ found=true; return thenPart.trim(); });
  // if false then ... else ... end → else節だけ残す
  modified=modified.replace(/\bif\s+false\s+then\s+[\s\S]*?\s*else\s+([\s\S]*?)\s*end\b/g,(_,elsePart)=>{ found=true; return elsePart.trim(); });
  // while false do ... end → 削除
  modified=modified.replace(/\bwhile\s+false\s+do\s+[\s\S]*?\s*end\b/g,()=>{ found=true; return ''; });
  // repeat ... until true → 1回実行（内容だけ残す）
  modified=modified.replace(/\brepeat\s+([\s\S]*?)\s*until\s+true\b/g,(_,body)=>{ found=true; return body.trim(); });
  if(!found) return { success:false, error:'デッドブランチが見つかりません', method:'dead_branch' };
  return { success:true, result:modified, method:'dead_branch' };
}

// ────────────────────────────────────────────────────────────────────────
//  #10  junkAssignmentCleaner  — 無意味代入・自己代入を削除
// ────────────────────────────────────────────────────────────────────────
function junkAssignmentCleaner(code) {
  let modified=code, found=false;
  // local a = a  (自己代入)
  modified=modified.replace(/local\s+(\w+)\s*=\s*\1\s*[\n;]/g,(_,name)=>{ found=true; return ''; });
  // local _ = ... (アンダースコア変数への代入)
  modified=modified.replace(/local\s+_\s*=\s*[^\n;]+[\n;]/g,()=>{ found=true; return ''; });
  // 連続する空行を1行に圧縮
  modified=modified.replace(/\n{3,}/g,'\n\n');
  if(!found) return { success:false, error:'ジャンク代入が見つかりません', method:'junk_clean' };
  return { success:true, result:modified, method:'junk_clean' };
}

// ────────────────────────────────────────────────────────────────────────
//  #11  duplicateConstantReducer  — 重複定数を1つにまとめる
// ────────────────────────────────────────────────────────────────────────
function duplicateConstantReducer(code) {
  let modified=code, found=false;
  // 同じ string.char(...) が3回以上出現する場合に変数化
  const scMap=new Map();
  modified.replace(/string\.char\([^)]+\)/g,m=>{ scMap.set(m,(scMap.get(m)||0)+1); });
  for(const [expr,count] of scMap) {
    if(count<3) continue;
    const varName=`_sc${Math.abs(hashCode(expr)&0xffff).toString(16)}`;
    // 変数宣言を先頭に追加し、使用箇所を置換
    const escapedExpr=expr.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    const re=new RegExp(escapedExpr,'g');
    if(re.test(modified)){
      modified=`local ${varName}=${expr}\n`+modified.replace(re,varName);
      found=true;
    }
  }
  if(!found) return { success:false, error:'重複定数が見つかりません', method:'dup_reduce' };
  return { success:true, result:modified, method:'dup_reduce' };
}

// ────────────────────────────────────────────────────────────────────────
//  #12  sandboxFilter  — 危険関数除去 + サイズ制限
// ────────────────────────────────────────────────────────────────────────
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
//  WereDev VM 解析システム  (#1〜#20)
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
//  #1  vmHookBootstrap  — Luaに注入するフック初期化コード
// ────────────────────────────────────────────────────────────────────────
const vmHookBootstrap = `
-- ══ YAJU VM Hook Bootstrap ══
__vm_logs = {}
__vm_log_count = 0
__vm_max_logs  = 2000   -- 無限ループ防止: 最大2000命令を記録

function __vmhook(ip, inst, stack, reg)
  if __vm_log_count >= __vm_max_logs then return end
  __vm_log_count = __vm_log_count + 1
  local entry = { ip = ip, ts = __vm_log_count }
  -- inst が table の場合は各フィールドを展開
  if type(inst) == "table" then
    entry.op   = inst[1]
    entry.arg1 = inst[2]
    entry.arg2 = inst[3]
    entry.arg3 = inst[4]
  elseif type(inst) == "number" then
    entry.op = inst
  end
  -- stack / reg はオプション（サイズ制限あり）
  if type(stack) == "table" and #stack <= 32 then
    local s = {}
    for i = 1, math.min(#stack, 8) do
      local v = stack[i]
      s[i] = type(v) == "number" and v or type(v)
    end
    entry.stack = s
  end
  if type(reg) == "table" then
    local r = {}
    for k, v in pairs(reg) do
      r[tostring(k)] = type(v) == "number" and v or type(v)
      if #r >= 8 then break end
    end
    entry.reg = r
  end
  table.insert(__vm_logs, entry)
end
-- ══ Bootstrap End ══
`;

// ────────────────────────────────────────────────────────────────────────
//  #7  vmDumpFooter  — 実行後に __vm_logs / bytecode を stdout に出力
// ────────────────────────────────────────────────────────────────────────
const vmDumpFooter = `
-- ══ YAJU VM Dump Footer ══
if __vm_log_count and __vm_log_count > 0 then
  for i, v in ipairs(__vm_logs) do
    local op   = tostring(v.op   or "nil")
    local arg1 = tostring(v.arg1 or "nil")
    local arg2 = tostring(v.arg2 or "nil")
    local arg3 = tostring(v.arg3 or "nil")
    print("__VMLOG__\t" .. tostring(v.ip) .. "\t" .. op .. "\t" .. arg1 .. "\t" .. arg2 .. "\t" .. arg3)
  end
  print("__VMLOG_END__\t" .. tostring(__vm_log_count))
end
-- ══ Dump End ══
`;

// ────────────────────────────────────────────────────────────────────────
//  #2  runLuaWithHooks  — hookコードをLuaコード先頭に注入
// ────────────────────────────────────────────────────────────────────────
function runLuaWithHooks(code) {
  return vmHookBootstrap + '\n' + code + '\n' + vmDumpFooter;
}

// ────────────────────────────────────────────────────────────────────────
//  #3  vmDetector 拡張  — WereDev特有パターンを追加
//  (既存vmDetectorを上書き)
// ────────────────────────────────────────────────────────────────────────
function vmDetector(code) {
  const hints = [];

  // WereDev VM 特有パターン (#3)
  const weredevPatterns = [
    { re: /while\s+true\s+do[\s\S]{0,400}bytecode\s*\[\s*ip\s*\]/i,  desc: 'WereDev: while-true + bytecode[ip]' },
    { re: /local\s+inst\s*=\s*bytecode\s*\[\s*ip\s*\]/,              desc: 'WereDev: local inst = bytecode[ip]' },
    { re: /inst\s*\[\s*1\s*\]/,                                        desc: 'WereDev: inst[1] opcode access' },
    { re: /inst\s*\[\s*2\s*\][\s\S]{0,100}inst\s*\[\s*3\s*\]/s,      desc: 'WereDev: inst[2]/inst[3] args' },
    { re: /ip\s*=\s*ip\s*\+\s*1/,                                     desc: 'WereDev: ip increment pattern' },
  ];

  // 汎用VMパターン
  const genericPatterns = [
    { re: /while\s+true\s+do[\s\S]{0,200}opcode/i,        desc: 'while-true opcodeループ' },
    { re: /\bopcode\b.*\bInstructions\b/s,                desc: 'opcode+Instructionsテーブル' },
    { re: /local\s+\w+\s*=\s*Instructions\s*\[/,         desc: 'Instructions配列アクセス' },
    { re: /\bProto\b[\s\S]{0,100}\bupValues\b/s,          desc: 'Proto/upValues構造体' },
    { re: /\bVStack\b|\bVEnv\b|\bVPC\b/,                  desc: '仮想スタック/環境変数' },
    { re: /if\s+opcode\s*==\s*\d+\s*then/,                desc: 'opcodeディスパッチ' },
    { re: /\{(\s*\d+\s*,){20,}/,                          desc: '大規模バイトコードテーブル' },
    { re: /\bbit\.bxor\b|\bbit\.band\b|\bbit\.bor\b/,     desc: 'ビット演算 (VM特徴)' },
  ];

  let weredevScore = 0;
  for (const p of weredevPatterns) {
    if (p.re.test(code)) { hints.push(p.desc); weredevScore++; }
  }
  if (/return\s*\(function\s*\([^)]*\)/s.test(code)) hints.push('自己実行関数ラッパー');
  for (const p of genericPatterns) {
    if (p.re.test(code)) hints.push(p.desc);
  }

  // 文字列抽出
  const strings = [];
  const strPattern = /"([^"\\]{4,}(?:\\.[^"\\]*)*)"/g;
  let m;
  while ((m = strPattern.exec(code)) !== null) { if (m[1].length > 4) strings.push(m[1]); }
  if (strings.length > 0) hints.push(`${strings.length}件の文字列リテラル`);

  const isWereDev = weredevScore >= 2;
  const isVm      = hints.length >= 2;

  return { isVm, isWereDev, weredevScore, hints, strings: strings.slice(0, 50), method: 'vm_detect' };
}
function deobfuscateVmify(code) {
  const r = vmDetector(code);
  if (!r.isVm && r.hints.length === 0)
    return { success: false, error: 'VMパターンが検出されませんでした', method: 'vmify' };
  return { success: true, result: code, hints: r.hints, strings: r.strings,
    isWereDev: r.isWereDev, weredevScore: r.weredevScore,
    warning: 'VM完全解読には動的実行+フック解析を推奨', method: 'vmify' };
}

// ────────────────────────────────────────────────────────────────────────
//  #4 / #5 / #6  injectVmHook  — VMループに __vmhook を注入
// ────────────────────────────────────────────────────────────────────────
function injectVmHook(code) {
  let modified = code;
  let injected = false;

  // #5: while true do の直後に __vmhook を挿入
  modified = modified.replace(
    /(while\s+true\s+do\s*\n)/g,
    (match) => {
      injected = true;
      return match + '  __vmhook(ip, inst, stack, reg)\n';
    }
  );

  // #6: local inst = bytecode[ip] の次行にフォールバックhookを挿入
  //     (while true do が見つからなかった場合のフォールバック)
  if (!injected) {
    modified = modified.replace(
      /(local\s+inst\s*=\s*bytecode\s*\[\s*ip\s*\][^\n]*\n)/g,
      (match) => {
        injected = true;
        return match + '  __vmhook(ip, inst)\n';
      }
    );
  }

  // 汎用フォールバック: opcode = ... の行の後
  if (!injected) {
    modified = modified.replace(
      /(local\s+opcode\s*=\s*[^\n]+\n)/g,
      (match) => {
        injected = true;
        return match + '  __vmhook(ip, opcode)\n';
      }
    );
  }

  return { code: modified, injected };
}

// ────────────────────────────────────────────────────────────────────────
//  #12 / #13 / #14  dumpBytecodeTables  — bytecodeテーブルをstdoutに出力
// ────────────────────────────────────────────────────────────────────────
function dumpBytecodeTables(code) {
  // #13: bytecodeCandidate = 要素50以上・数値のみの配列を検出
  const candidates = [];
  const tblPat = /local\s+(\w+)\s*=\s*\{([\s\d,]+)\}/g;
  let m;
  while ((m = tblPat.exec(code)) !== null) {
    const name = m[1];
    const nums = m[2].split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
    if (nums.length >= 50) candidates.push({ name, count: nums.length });
  }
  if (candidates.length === 0) return { code, injected: false, candidates: [] };

  // #14: for ループでstdoutに出力するLuaコードを末尾に挿入
  let inject = '\n-- ══ YAJU Bytecode Dump ══\n';
  for (const c of candidates) {
    inject += `if type(${c.name}) == "table" then\n`;
    inject += `  for __i, __v in ipairs(${c.name}) do\n`;
    inject += `    print("__BYTECODE__\t${c.name}\t" .. tostring(__i) .. "\t" .. tostring(__v))\n`;
    inject += `  end\n`;
    inject += `end\n`;
  }

  return { code: code + inject, injected: true, candidates };
}

// ────────────────────────────────────────────────────────────────────────
//  #8 / #9  parseVmLogs  — stdout から __VMLOG__ 行を抽出
// ────────────────────────────────────────────────────────────────────────
function parseVmLogs(stdout) {
  const vmTrace = [];
  const lines = stdout.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('__VMLOG__')) continue;
    const parts = trimmed.split('\t');
    if (parts.length < 2) continue;
    // フォーマット: __VMLOG__ \t ip \t op \t arg1 \t arg2 \t arg3
    const ip   = parseInt(parts[1]) || 0;
    const op   = parts[2] !== 'nil' ? (isNaN(parseInt(parts[2])) ? parts[2] : parseInt(parts[2])) : null;
    const arg1 = parts[3] !== 'nil' ? (isNaN(parseInt(parts[3])) ? parts[3] : parseInt(parts[3])) : null;
    const arg2 = parts[4] !== 'nil' ? (isNaN(parseInt(parts[4])) ? parts[4] : parseInt(parts[4])) : null;
    const arg3 = parts[5] !== 'nil' ? (isNaN(parseInt(parts[5])) ? parts[5] : parseInt(parts[5])) : null;
    vmTrace.push({ ip, op, arg1, arg2, arg3 });
  }
  return vmTrace;
}

// ────────────────────────────────────────────────────────────────────────
//  #15  parseBytecodeDump  — stdout から __BYTECODE__ 行を抽出
// ────────────────────────────────────────────────────────────────────────
function parseBytecodeDump(stdout) {
  // tableName -> number[]
  const bytecodeDump = {};
  const lines = stdout.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('__BYTECODE__')) continue;
    const parts = trimmed.split('\t');
    if (parts.length < 4) continue;
    const tblName = parts[1];
    const idx     = parseInt(parts[2]);
    const val     = parseInt(parts[3]);
    if (!bytecodeDump[tblName]) bytecodeDump[tblName] = [];
    bytecodeDump[tblName][idx - 1] = val; // 1-indexed -> 0-indexed
  }
  return bytecodeDump;
}

// ────────────────────────────────────────────────────────────────────────
//  #10  WereDev VM 検出しきい値チェック
// ────────────────────────────────────────────────────────────────────────
const VM_TRACE_THRESHOLD = 50;

function checkWereDevDetected(vmTrace) {
  return vmTrace.length >= VM_TRACE_THRESHOLD;
}

// ────────────────────────────────────────────────────────────────────────
//  #11  vmTraceAnalyzer  — opcode頻度分析・opcodeMap生成
// ────────────────────────────────────────────────────────────────────────
function vmTraceAnalyzer(vmTrace) {
  if (!vmTrace || vmTrace.length === 0)
    return { success: false, error: 'vmTraceが空です', opcodeMap: {} };

  // opcode 頻度カウント
  const freq = {};
  for (const entry of vmTrace) {
    if (entry.op === null || entry.op === undefined) continue;
    const key = String(entry.op);
    freq[key] = (freq[key] || 0) + 1;
  }

  // 頻度順にソート
  const sorted = Object.entries(freq)
    .sort((a, b) => b[1] - a[1])
    .map(([op, count]) => ({ op: isNaN(op) ? op : parseInt(op), count }));

  // opcodeMap: opcode番号 -> 推定命令名
  const opcodeMap = buildOpcodeMap(sorted, vmTrace);

  // ipの変化から制御フロー推測
  const ipJumps = [];
  for (let i = 1; i < vmTrace.length; i++) {
    const delta = vmTrace[i].ip - vmTrace[i-1].ip;
    if (delta !== 1 && delta !== 0) ipJumps.push({ from: vmTrace[i-1].ip, to: vmTrace[i].ip, delta });
  }

  return {
    success: true,
    totalInstructions: vmTrace.length,
    uniqueOpcodes: sorted.length,
    opcodeFrequency: sorted.slice(0, 20),
    opcodeMap,
    ipJumps: ipJumps.slice(0, 20),
    method: 'vm_trace_analyze',
  };
}

// ────────────────────────────────────────────────────────────────────────
//  #16 / #17 / #18  instructionStructureAnalyzer + opcodeMap生成
// ────────────────────────────────────────────────────────────────────────

// 一般的なLua VMオペコードの番号→名前マッピング（Lua5.1標準）
const LUA51_OPCODES = {
  0:'MOVE', 1:'LOADK', 2:'LOADBOOL', 3:'LOADNIL', 4:'GETUPVAL',
  5:'GETGLOBAL', 6:'GETTABLE', 7:'SETGLOBAL', 8:'SETUPVAL', 9:'SETTABLE',
  10:'NEWTABLE', 11:'SELF', 12:'ADD', 13:'SUB', 14:'MUL',
  15:'DIV', 16:'MOD', 17:'POW', 18:'UNM', 19:'NOT',
  20:'LEN', 21:'CONCAT', 22:'JMP', 23:'EQ', 24:'LT',
  25:'LE', 26:'TEST', 27:'TESTSET', 28:'CALL', 29:'TAILCALL',
  30:'RETURN', 31:'FORLOOP', 32:'FORPREP', 33:'TFORLOOP', 34:'SETLIST',
  35:'CLOSE', 36:'CLOSURE', 37:'VARARG',
};

function buildOpcodeMap(sortedFreq, vmTrace) {
  const opcodeMap = {};

  // #16: inst[1]/inst[2]/inst[3] の構造推測
  // 最頻出opcodeを解析して位置を推定
  for (const { op } of sortedFreq) {
    const opNum = parseInt(op);
    if (!isNaN(opNum) && LUA51_OPCODES[opNum]) {
      opcodeMap[op] = LUA51_OPCODES[opNum];
    }
  }

  // #17: opcodeIndex推測
  // vmTrace内でarg1/arg2/arg3の分布を見て命令構造を推定
  const arg1Stats = analyzeArgStats(vmTrace.map(t => t.arg1));
  const arg2Stats = analyzeArgStats(vmTrace.map(t => t.arg2));
  const opcodeIndex = inferOpcodeIndex(vmTrace, arg1Stats, arg2Stats);

  // #18: opcodeExecutionMap生成
  const opcodeExecutionMap = {};
  for (const [num, name] of Object.entries(LUA51_OPCODES)) {
    const opEntries = vmTrace.filter(t => String(t.op) === String(num));
    if (opEntries.length > 0) {
      opcodeExecutionMap[name] = {
        opcode: parseInt(num),
        count: opEntries.length,
        sampleArgs: opEntries.slice(0, 3).map(e => [e.arg1, e.arg2, e.arg3]),
      };
    }
  }

  return { map: opcodeMap, opcodeIndex, opcodeExecutionMap };
}

function analyzeArgStats(args) {
  const nums = args.filter(a => typeof a === 'number');
  if (nums.length === 0) return { min: 0, max: 0, avg: 0, isRegister: false };
  const min = Math.min(...nums);
  const max = Math.max(...nums);
  const avg = nums.reduce((a, b) => a + b, 0) / nums.length;
  const isRegister = max < 256 && min >= 0; // レジスタっぽい範囲
  return { min, max, avg: Math.round(avg), isRegister };
}

function inferOpcodeIndex(vmTrace, arg1Stats, arg2Stats) {
  // op フィールドが存在する場合はそれが opcodeIndex=0 (inst[1])
  const hasDirectOp = vmTrace.some(t => t.op !== null && t.op !== undefined);
  if (hasDirectOp) return { position: 1, confidence: 'high', note: 'inst[1]がopcode' };

  // arg1が小さい整数の場合はarg1がopcodeの可能性
  if (arg1Stats.max < 40 && arg1Stats.isRegister)
    return { position: 1, confidence: 'medium', note: 'arg1がopcode候補' };

  return { position: 1, confidence: 'low', note: '推定不能' };
}

// ────────────────────────────────────────────────────────────────────────
//  #19  reconstructedLuaBuilder  — 疑似Luaコードを再構築
// ────────────────────────────────────────────────────────────────────────
function reconstructedLuaBuilder(vmTrace, bytecodeDump, opcodeMap) {
  if (!vmTrace || vmTrace.length === 0)
    return { success: false, error: 'vmTraceが空', pseudoCode: '' };

  const map    = (opcodeMap && opcodeMap.map) || {};
  const exMap  = (opcodeMap && opcodeMap.opcodeExecutionMap) || {};
  const lines  = ['-- ══ YAJU Reconstructed Pseudo-Lua ══'];
  lines.push(`-- 解析命令数: ${vmTrace.length}, ユニークop: ${new Set(vmTrace.map(t => t.op)).size}`);
  lines.push('');

  let prevIp = -1;
  const ipToLine = {};

  for (const entry of vmTrace) {
    const { ip, op, arg1, arg2, arg3 } = entry;
    const opName = (op !== null && op !== undefined) ? (map[String(op)] || `OP_${op}`) : 'UNKNOWN';

    // IP変化によるジャンプ検出
    if (prevIp >= 0 && ip !== prevIp + 1) {
      if (ip < prevIp) lines.push(`  -- << JUMP BACK to ip=${ip} (loop?) >>`);
      else if (ip > prevIp + 1) lines.push(`  -- >> JUMP FORWARD to ip=${ip} (skip ${ip-prevIp-1}) >>`);
    }

    let pseudoLine = `  -- [ip=${ip}] ${opName}`;

    // 命令ごとに疑似コードを生成
    switch (opName) {
      case 'MOVE':
        pseudoLine = `  reg[${arg1}] = reg[${arg2}]  -- MOVE R${arg1} R${arg2}`;
        break;
      case 'LOADK':
        pseudoLine = `  reg[${arg1}] = K[${arg2}]  -- LOADK R${arg1} K${arg2}`;
        break;
      case 'LOADBOOL':
        pseudoLine = `  reg[${arg1}] = ${arg2 ? 'true' : 'false'}  -- LOADBOOL`;
        break;
      case 'LOADNIL':
        pseudoLine = `  for i=${arg1},${arg2} do reg[i]=nil end  -- LOADNIL`;
        break;
      case 'GETGLOBAL':
        pseudoLine = `  reg[${arg1}] = _G[K[${arg2}]]  -- GETGLOBAL`;
        break;
      case 'SETGLOBAL':
        pseudoLine = `  _G[K[${arg2}]] = reg[${arg1}]  -- SETGLOBAL`;
        break;
      case 'GETTABLE':
        pseudoLine = `  reg[${arg1}] = reg[${arg2}][R/K(${arg3})]  -- GETTABLE`;
        break;
      case 'SETTABLE':
        pseudoLine = `  reg[${arg1}][R/K(${arg2})] = R/K(${arg3})  -- SETTABLE`;
        break;
      case 'ADD':
        pseudoLine = `  reg[${arg1}] = R/K(${arg2}) + R/K(${arg3})  -- ADD`;
        break;
      case 'SUB':
        pseudoLine = `  reg[${arg1}] = R/K(${arg2}) - R/K(${arg3})  -- SUB`;
        break;
      case 'MUL':
        pseudoLine = `  reg[${arg1}] = R/K(${arg2}) * R/K(${arg3})  -- MUL`;
        break;
      case 'DIV':
        pseudoLine = `  reg[${arg1}] = R/K(${arg2}) / R/K(${arg3})  -- DIV`;
        break;
      case 'MOD':
        pseudoLine = `  reg[${arg1}] = R/K(${arg2}) % R/K(${arg3})  -- MOD`;
        break;
      case 'CONCAT':
        pseudoLine = `  reg[${arg1}] = reg[${arg2}]..reg[${arg3}]  -- CONCAT`;
        break;
      case 'JMP':
        pseudoLine = `  goto ip+${arg2}+1  -- JMP offset=${arg2}`;
        break;
      case 'EQ':
        pseudoLine = `  if (R/K(${arg2}) == R/K(${arg3})) ~= ${arg1?'true':'false'} then skip  -- EQ`;
        break;
      case 'LT':
        pseudoLine = `  if (R/K(${arg2}) < R/K(${arg3})) ~= ${arg1?'true':'false'} then skip  -- LT`;
        break;
      case 'LE':
        pseudoLine = `  if (R/K(${arg2}) <= R/K(${arg3})) ~= ${arg1?'true':'false'} then skip  -- LE`;
        break;
      case 'CALL':
        pseudoLine = `  reg[${arg1}..${arg1}+${arg3?arg3-1:0}] = reg[${arg1}](reg[${arg1}+1]..reg[${arg1}+${arg2?arg2-1:0}])  -- CALL`;
        break;
      case 'RETURN':
        pseudoLine = `  return reg[${arg1}..${arg1}+${arg2?arg2-2:0}]  -- RETURN`;
        break;
      case 'FORLOOP':
        pseudoLine = `  -- FORLOOP R${arg1} -> ip+=${arg2}`;
        break;
      case 'FORPREP':
        pseudoLine = `  -- FORPREP R${arg1} skip=${arg2}`;
        break;
      case 'NEWTABLE':
        pseudoLine = `  reg[${arg1}] = {}  -- NEWTABLE`;
        break;
      case 'SETLIST':
        pseudoLine = `  -- SETLIST reg[${arg1}][${arg3}*50+1..] = reg[${arg1}+1..]`;
        break;
      case 'CLOSURE':
        pseudoLine = `  reg[${arg1}] = closure(proto[${arg2}])  -- CLOSURE`;
        break;
      case 'VARARG':
        pseudoLine = `  reg[${arg1}..${arg1}+${arg2?arg2-1:0}] = vararg  -- VARARG`;
        break;
      default:
        pseudoLine = `  -- [ip=${ip}] ${opName}(${[arg1,arg2,arg3].filter(v=>v!==null).join(', ')})`;
    }

    lines.push(pseudoLine);
    ipToLine[ip] = pseudoLine;
    prevIp = ip;
  }

  lines.push('');
  lines.push('-- ══ End of Reconstruction ══');

  // 重複を削減してコンパクトに
  const unique = [];
  const seen = new Set();
  for (const l of lines) {
    if (!seen.has(l) || l.startsWith('--')) { unique.push(l); seen.add(l); }
  }

  return {
    success: true,
    pseudoCode: unique.join('\n'),
    instructionCount: vmTrace.length,
    method: 'vm_reconstruct',
  };
}

// ────────────────────────────────────────────────────────────────────────
//  vmBytecodeExtractor  (上書き: より詳細な抽出)
// ────────────────────────────────────────────────────────────────────────
function vmBytecodeExtractor(code) {
  const tables = [];
  const tblPattern = /local\s+(\w+)\s*=\s*\{((?:\s*\d+\s*,){10,}[^}]*)\}/g;
  let m;
  while ((m = tblPattern.exec(code)) !== null) {
    const name = m[1];
    const nums = m[2].split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
    if (nums.length >= 10) {
      // バイトコードらしさのスコア計算
      const max = Math.max(...nums);
      const isLikelyBytecode = max < 65536 && nums.length >= 20;
      tables.push({ name, count: nums.length, sample: nums.slice(0, 16), isLikelyBytecode });
    }
  }
  if (tables.length === 0) return { success: false, error: 'バイトコードテーブルが見つかりません', method: 'vm_extract' };
  return {
    success: true, tables, method: 'vm_extract',
    hints: tables.map(t => `${t.name}[${t.count}要素]${t.isLikelyBytecode?' (bytecode候補)':''}: [${t.sample.join(',')}...]`),
  };
}


// ────────────────────────────────────────────────────────────────────────
//  #16  stringTransformDecoder  — string.reverse/string.sub 型難読化復元
// ────────────────────────────────────────────────────────────────────────
function stringTransformDecoder(code) {
  let modified=code, found=false;
  const env=new SymbolicEnv();
  // string.reverse("...") を直接評価
  modified=modified.replace(/string\.reverse\s*\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*\)/g,(match,strExpr)=>{
    const s=stripLuaString(strExpr); if(s===null) return match;
    found=true;
    const rev=s.split('').reverse().join('');
    return `"${rev.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`;
  });
  // string.sub("...", i, j)
  modified=modified.replace(/string\.sub\s*\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*,\s*(-?\d+)\s*(?:,\s*(-?\d+))?\s*\)/g,(match,strExpr,iStr,jStr)=>{
    const s=stripLuaString(strExpr); if(s===null) return match;
    let i=parseInt(iStr),j=jStr!==undefined?parseInt(jStr):s.length;
    if(i<0) i=Math.max(0,s.length+i+1); if(j<0) j=s.length+j+1;
    found=true;
    const sub=s.slice(i-1,j);
    return `"${sub.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`;
  });
  // string.rep("...", n)
  modified=modified.replace(/string\.rep\s*\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*,\s*(\d+)\s*\)/g,(match,strExpr,nStr)=>{
    const s=stripLuaString(strExpr); const n=parseInt(nStr);
    if(s===null||isNaN(n)) return match;
    found=true;
    return `"${s.repeat(n).replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`;
  });
  if(!found) return { success:false, error:'stringTransformパターンが見つかりません', method:'str_transform' };
  return { success:true, result:modified, method:'str_transform' };
}

// ────────────────────────────────────────────────────────────────────────
//  #17  base64Detector  — Base64文字列を自動デコード
// ────────────────────────────────────────────────────────────────────────
function base64Detector(code, pool) {
  const B64_RE=/[A-Za-z0-9+\/]{32,}={0,2}/g;
  const found=[]; let m;
  while((m=B64_RE.exec(code))!==null){
    const b64=m[0];
    try {
      const decoded=Buffer.from(b64,'base64').toString('utf8');
      // デコード結果がLuaコードっぽければプールに追加
      if(scoreLuaCode(decoded)>20){
        if(pool) pool.add(decoded,'base64_decode');
        found.push({ b64:b64.substring(0,30)+'...', score:scoreLuaCode(decoded).toFixed(1), decoded:decoded.substring(0,60) });
      }
    } catch {}
  }
  if(found.length===0) return { success:false, error:'Base64Luaコードが見つかりません', method:'base64_detect' };
  return { success:true, found, hints:found.map(f=>`score=${f.score}: "${f.decoded}..."`), method:'base64_detect' };
}

// ────────────────────────────────────────────────────────────────────────
//  EncryptStrings  (後方互換 + charDecoder統合)
// ────────────────────────────────────────────────────────────────────────
function deobfuscateEncryptStrings(code) {
  const env=new SymbolicEnv();
  let res=charDecoder(code,env);
  if(res.success) return res;
  // フォールバック: 数値エスケープ展開
  let modified=code, found=false;
  modified=modified.replace(/"((?:\\[0-9]{1,3}|\\x[0-9a-fA-F]{2}|[^"\\])+)"/g,(match,inner)=>{
    if(!/\\[0-9]|\\x/i.test(inner)) return match;
    try {
      const decoded=resolveLuaStringEscapes(inner);
      if([...decoded].every(c=>c.charCodeAt(0)>=32&&c.charCodeAt(0)<=126)){
        found=true; return `"${decoded.replace(/"/g,'\\"').replace(/\\/g,'\\\\')}"`;
      }
    } catch {}
    return match;
  });
  if(!found) return { success:false, error:'EncryptStringsパターンが見つかりません', method:'encrypt_strings' };
  return { success:true, result:modified, method:'encrypt_strings' };
}

// ════════════════════════════════════════════════════════════════════════
//  #18 + #19  recursiveDeobfuscate  — 再帰的解析 + seenCodeCache
// ════════════════════════════════════════════════════════════════════════
function recursiveDeobfuscate(code, maxDepth, pool) {
  maxDepth=maxDepth||8;
  pool=pool||new CapturePool();
  const seenHashes=new Set();

  // 静的パスのリスト（処理順: #1の要件に対応）
  const staticPasses=[
    { name:'ConstantFolding',    fn: c=>evaluateExpressions(c) },
    { name:'EvalExpressions',    fn: c=>evaluateExpressions(c) },
    { name:'SplitStrings',       fn: c=>deobfuscateSplitStrings(c) },
    { name:'XOR',                fn: c=>xorDecoder(c) },
    { name:'ConstantArray',      fn: c=>constantArrayResolver(c) },
    { name:'CharDecoder',        fn: c=>charDecoder(c) },
    { name:'MathEval',           fn: c=>mathEvaluator(c) },
    { name:'ConstantCall',       fn: c=>constantCallEvaluator(c) },
    { name:'StringTransform',    fn: c=>stringTransformDecoder(c) },
    { name:'DeadBranch',         fn: c=>deadBranchRemover(c) },
    { name:'JunkClean',          fn: c=>junkAssignmentCleaner(c) },
  ];

  let current=code;
  let depth=0;
  const allSteps=[];

  while(depth++<maxDepth){
    const h=cacheHash(current);
    if(seenHashes.has(h)) break;
    seenHashes.add(h);

    // キャッシュチェック
    const cached=cacheGet(current);
    if(cached){ current=cached; allSteps.push({step:'CacheHit',success:true,method:'cache'}); break; }

    let anyChange=false;
    for(const pass of staticPasses){
      const res=pass.fn(current);
      if(res.success&&res.result&&res.result!==current){
        allSteps.push({ step:pass.name, success:true, method:res.method });
        pool.add(res.result, pass.name);
        current=res.result;
        anyChange=true;
      }
    }

    // base64チェック
    base64Detector(current, pool);

    if(!anyChange) break;
  }

  // キャッシュに保存
  if(current!==code) cacheSet(code, current);

  return { code:current, steps:allSteps, pool };
}

// ════════════════════════════════════════════════════════════════════════
//  advancedStaticDeobfuscate  — 全パス統合エントリーポイント
// ════════════════════════════════════════════════════════════════════════
function advancedStaticDeobfuscate(code) {
  const pool=new CapturePool();
  const { code:result, steps } = recursiveDeobfuscate(code, 8, pool);
  const changed=result!==code;
  return {
    success: changed,
    result,
    steps: steps.map(s=>s.step),
    method: 'advanced_static',
    error: changed?undefined:'静的解析で変化なし（動的実行が必要な可能性があります）',
  };
}

// deepStaticDeobfuscate (後方互換)
function deepStaticDeobfuscate(code, maxDepth) {
  const { code:result, steps } = recursiveDeobfuscate(code, maxDepth||6, new CapturePool());
  return { code:result, changed:result!==code };
}

// symbolicExecute, SymbolicEnv (後方互換エクスポート用スタブ)
function symbolicExecute(code, env, depth, visited) {
  const res=recursiveDeobfuscate(code, 2, new CapturePool());
  return { code:res.code, env:env||new SymbolicEnv(), changed:res.code!==code };
}





// ════════════════════════════════════════════════════════
//  AUTO  — v3 解析パイプライン
//
//  処理順 (#1要件):
//   1. advanced_static (ConstantFolding / SymExec / 全静的パス)
//   2. evaluate_expressions
//   3. split_strings
//   4. xor
//   5. constant_array
//   6. dynamic (Lua実行 → 多段ループ)
//   7. vmify (VM検出ヒント)
// ════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════
//  autoDeobfuscate  v4  — 全10項目対応パイプライン
//
//  処理順:
//   ① dynamicDecode (loadstring hook, safeEnv, __DECODED__ dump) ← #1/#2 最初に配置
//   ② loaderPatternDetected チェック → true なら VM解析スキップ   ← #7/#8
//   ③ 静的解析群 (advanced_static, eval, split, xor, constantArray)
//   ④ VM検出 → dynamicDecode結果に対してのみ実行                  ← #1/#5
//   ⑤ VM解析 (vmTraceAnalyzer, reconstructedLuaBuilder)
//   ⑥ #10: decode結果がLuaコードなら再帰パイプライン実行
// ════════════════════════════════════════════════════════════════════════

async function autoDeobfuscate(code, _depth) {
  const depth   = _depth || 0;
  const results = [];
  let current   = code;
  const luaBin  = checkLuaAvailable();
  const pool    = new CapturePool();
  pool.add(current, 'input');

  // ══════════════════════════════════════════════════════
  //  ① dynamicDecode — pipeline最初 (#1/#2)
  //    loadstring/load を hookして __DECODED__ をダンプ
  // ══════════════════════════════════════════════════════
  let dynDecodedResult  = null;
  let dynVmAnalysis     = null;
  let wereDevDetected   = false;

  if (luaBin) {
    const dynRes = await dynamicDecode(current);
    results.push({
      step: `dynamicDecode${depth > 0 ? ` (再帰${depth}回目)` : ''}`,
      success: dynRes.success,
      result: dynRes.result,
      method: dynRes.method,
      error: dynRes.error,
      decodedCount: dynRes.decodedCount,
      WereDevVMDetected: dynRes.WereDevVMDetected,
    });

    if (dynRes.success && dynRes.result) {
      dynDecodedResult = dynRes.result;
      dynVmAnalysis    = dynRes.vmAnalysis || null;
      wereDevDetected  = !!(dynRes.WereDevVMDetected || (dynVmAnalysis && dynVmAnalysis.wereDevDetected));
      current          = dynRes.result;
      pool.add(current, 'dynamic_decode');
    }
  } else {
    results.push({ step: 'dynamicDecode', success: false, error: 'Luaがインストールされていません', method: 'dynamic_decode' });
  }

  // ══════════════════════════════════════════════════════
  //  ② loaderPatternDetected チェック (#7/#8)
  //    table.concat + string.char + loadstring が揃う → VM解析スキップ
  // ══════════════════════════════════════════════════════
  const isLoaderPattern = loaderPatternDetected(code); // 元コードに対してチェック
  results.push({
    step: 'LoaderPatternCheck',
    success: true,
    method: 'loader_pattern',
    loaderPattern: isLoaderPattern,
    hints: isLoaderPattern ? ['table.concat+string.char+loadstringパターン検出 → VM解析スキップ'] : [],
  });

  // ══════════════════════════════════════════════════════
  //  ③ 静的解析群 (loaderPatternでも実行: 静的は常に有益)
  // ══════════════════════════════════════════════════════
  {
    const advRes = advancedStaticDeobfuscate(current);
    results.push({
      step: 'AdvancedStatic',
      success: advRes.success,
      result: advRes.result,
      method: advRes.method,
      hints: advRes.steps && advRes.steps.length ? [`ステップ: ${advRes.steps.join(' → ')}`] : undefined,
    });
    if (advRes.success && advRes.result && advRes.result !== current) {
      current = advRes.result;
      pool.add(current, 'advanced_static');
    }
  }
  for (const [name, fn] of [
    ['EvaluateExpressions', evaluateExpressions],
    ['SplitStrings',        deobfuscateSplitStrings],
    ['XOR',                 xorDecoder],
    ['ConstantArray',       constantArrayResolver],
  ]) {
    const res = fn(current);
    results.push({ step: name, ...res });
    if (res.success && res.result && res.result !== current) {
      current = res.result;
      pool.add(current, name.toLowerCase());
    }
  }

  // 静的解析後に再度 dynamicDecode を試みる（静的で変化があった場合のみ）
  if (luaBin && current !== code && !dynDecodedResult) {
    const dynRes2 = await dynamicDecode(current);
    results.push({ step: 'dynamicDecode (post-static)', ...dynRes2 });
    if (dynRes2.success && dynRes2.result) {
      current       = dynRes2.result;
      dynDecodedResult = dynRes2.result;
      pool.add(current, 'dynamic_post_static');
    }
  }

  // ══════════════════════════════════════════════════════
  //  ④/#5 VM検出 — dynamicDecode結果コードに対してのみ (#5)
  //       loaderPatternDetected の場合はスキップ (#8)
  // ══════════════════════════════════════════════════════
  if (!isLoaderPattern) {
    // VM検出対象: dynamicDecodeの結果 or 現在のコード
    const vmTarget = dynDecodedResult || current;
    const vmRes    = deobfuscateVmify(vmTarget);

    if (vmRes.success) {
      results.push({ step: 'VmDetect', ...vmRes });

      // バイトコード抽出
      const vmEx = vmBytecodeExtractor(vmTarget);
      if (vmEx.success) results.push({ step: 'VmBytecodeExtract', ...vmEx });

      // ⑤ VM深層解析 — dynVmAnalysis か vmAnalysis から vmTrace を取得
      const vmAnalysis = dynVmAnalysis ||
        results.map(r => r.vmAnalysis).find(a => a && a.vmTrace && a.vmTrace.length > 0);

      if (vmAnalysis && vmAnalysis.vmTrace && vmAnalysis.vmTrace.length > 0) {
        const { vmTrace, bytecodeDump } = vmAnalysis;
        const traceResult = vmTraceAnalyzer(vmTrace);
        results.push({ step: 'VmTraceAnalyzer', ...traceResult });

        if (wereDevDetected || vmTrace.length >= 10) {
          const reconResult = reconstructedLuaBuilder(vmTrace, bytecodeDump, traceResult.opcodeMap);
          results.push({ step: 'VmReconstruct', ...reconResult });
          if (reconResult.success && reconResult.pseudoCode) {
            current = reconResult.pseudoCode;
            pool.add(current, 'vm_reconstruct');
          }
        }
      } else if (vmRes.isWereDev || vmRes.isVm) {
        // 静的 bytecodeCandidate 抽出
        const tblPat = /local\s+(\w+)\s*=\s*\{([\s\d,]+)\}/g;
        const candidates = [];
        let m2;
        while ((m2 = tblPat.exec(vmTarget)) !== null) {
          const nums = m2[2].split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
          if (nums.length >= 50) candidates.push({ name: m2[1], count: nums.length });
        }
        if (candidates.length > 0) {
          results.push({
            step: 'BytecodeCandidate',
            success: true,
            method: 'bytecode_static',
            hints: candidates.map(c => `${c.name}[${c.count}要素]`),
          });
        }
      }
    }
  } else {
    // #8: loaderPattern → VM解析スキップ、dynamicDecodeのみ
    results.push({
      step: 'VmDetect (skipped)',
      success: false,
      method: 'vm_detect_skipped',
      error: 'loaderPatternDetected: VM解析スキップ',
    });
  }

  // base64検出
  {
    const b64res = base64Detector(current, pool);
    if (b64res.success) results.push({ step: 'Base64Detect', ...b64res });
  }

  // ══════════════════════════════════════════════════════
  //  ⑥ #10: decode結果がLuaコードなら再帰パイプライン実行
  //         最大4回、スコアが改善した場合のみ
  // ══════════════════════════════════════════════════════
  const MAX_RECURSIVE_DEPTH = 4;
  if (depth < MAX_RECURSIVE_DEPTH && luaBin) {
    const prevScore  = scoreLuaCode(code);
    const currScore  = scoreLuaCode(current);
    const stillObfuscated = /loadstring|load\s*\(|[A-Za-z0-9+\/]{60,}={0,2}/.test(current);

    // スコアが改善 かつ まだ難読化されている兆候がある場合
    if (stillObfuscated && currScore > prevScore + 10 && current !== code) {
      const recurseRes = await autoDeobfuscate(current, depth + 1);
      results.push({
        step: `RecursivePipeline (depth=${depth + 1})`,
        success: recurseRes.success,
        method: 'recursive_pipeline',
        hints: [`再帰解析: ${recurseRes.steps.length}ステップ, スコア改善: ${prevScore.toFixed(0)}→${currScore.toFixed(0)}`],
      });
      if (recurseRes.finalCode && recurseRes.finalCode !== current) {
        current = recurseRes.finalCode;
        pool.add(current, `recursive_${depth + 1}`);
        // 再帰結果のステップも追加
        for (const s of recurseRes.steps) {
          results.push({ ...s, step: `  [depth${depth+1}] ${s.step}` });
        }
      }
    }
  }

  return {
    success: results.some(r => r.success && r.result),
    steps: results,
    finalCode: current,
    poolSize: pool.entries.length,
    depth,
  };
}



// ════════════════════════════════════════════════════════
//  Prometheus 難読化
// ════════════════════════════════════════════════════════
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
