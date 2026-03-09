// core/detector.js
'use strict';

const { scoreLuaCode } = require('../utils/luaPrinter');

function loaderPatternDetected(code) {
  // パターン1: loadstring + table.concat + string.char
  const p1 = /table\.concat\s*\(/.test(code) &&
              /string\.char\s*\(/.test(code) &&
              /\bloadstring\b|\bload\s*\(/.test(code);
  // パターン2: load + char table (compact style)
  const p2 = /\bload\s*\(\s*\{/.test(code) ||
             (/\bload\s*\(/.test(code) && /\bstring\.char\b/.test(code));
  // パターン3: 巨大 string.char 連結 (50文字以上)
  const p3 = /string\.char\s*\(\s*\d[\d\s,]{40,}\)/.test(code);
  // パターン4: table.concat + number array
  const p4 = /table\.concat\s*\(\s*\{[\s\d,]+\}/.test(code);
  return p1 || p2 || p3 || p4;
}

// ────────────────────────────────────────────────────────────────────────
//  #4/#5  safeEnvPreamble 強化版 — 完全サンドボックス環境
// ────────────────────────────────────────────────────────────────────────
function vmDetector(code) {
  const hints = [];

  // ── WereDev (#22) + 項目5/9追加 ────────────────────────────────────
  const weredevPatterns = [
    { re: /bytecode\s*\[\s*ip\s*\]/,                                  desc: 'WereDev: bytecode[ip]' },
    { re: /dispatch\s*\[\s*inst\s*\[\s*1\s*\]\s*\]/,                 desc: 'WereDev: dispatch[inst[1]]' },
    { re: /\bvm_loop\b/,                                              desc: 'WereDev: vm_loop' },
    { re: /while\s+true\s+do[\s\S]{0,400}bytecode\s*\[\s*ip\s*\]/i,  desc: 'WereDev: while-true+bytecode[ip]' },
    { re: /local\s+inst\s*=\s*bytecode\s*\[\s*ip\s*\]/,              desc: 'WereDev: local inst=bytecode[ip]' },
    { re: /inst\s*\[\s*1\s*\]/,                                       desc: 'WereDev: inst[1]' },
    { re: /ip\s*=\s*ip\s*\+\s*1/,                                    desc: 'WereDev: ip+1' },
    // 項目5: while true do / while 1 do + B[pc]
    { re: /while\s*(?:true|1)\s*do[\s\S]{0,200}\bB\s*\[/,            desc: 'WereDev: while(true/1)+B[pc]' },
    // 項目5: local l = B[...] パターン
    { re: /local\s+l\s*=\s*\w+\s*\[\s*\w+\s*\]/,                    desc: 'WereDev: local l=B[pc]' },
    // 項目9: return(function トリガー
    { re: /return\s*\(\s*function\s*\(/,                              desc: 'WereDev: return(function' },
  ];

  // ── MoonSec (#20) ──────────────────────────────────────────────────
  const moonSecPatterns = [
    { re: /MoonSec/,                                                  desc: 'MoonSec: MoonSec識別子' },
    { re: /MSVM/,                                                     desc: 'MoonSec: MSVM' },
    { re: /_ENV\s*\[.+\]/,                                            desc: 'MoonSec: _ENV[key]アクセス' },
    { re: /dispatch\s*\[opcode\]/,                                    desc: 'MoonSec: dispatch[opcode]' },
    { re: /stk\s*\[top\]|stk\s*\[top\s*-/,                          desc: 'MoonSec: stack top操作' },
  ];

  // ── Luraph (#21) ───────────────────────────────────────────────────
  const luraphPatterns = [
    { re: /LPH_String/,                                               desc: 'Luraph: LPH_String' },
    { re: /LPH_GetEnv/,                                               desc: 'Luraph: LPH_GetEnv' },
    { re: /LPH_JIT/,                                                  desc: 'Luraph: LPH_JIT' },
    { re: /\bLPH\b/,                                                  desc: 'Luraph: LPH識別子' },
  ];

  // ── 汎用VM ─────────────────────────────────────────────────────────
  const genericPatterns = [
    { re: /while\s+true\s+do[\s\S]{0,200}opcode/i,  desc: 'generic: while-true opcode' },
    { re: /\bopcode\b.*\bInstructions\b/s,           desc: 'generic: opcode+Instructions' },
    { re: /local\s+\w+\s*=\s*Instructions\s*\[/,    desc: 'generic: Instructions配列' },
    { re: /\bProto\b[\s\S]{0,100}\bupValues\b/s,     desc: 'generic: Proto/upValues' },
    { re: /\bVStack\b|\bVEnv\b|\bVPC\b/,             desc: 'generic: 仮想スタック' },
    { re: /if\s+opcode\s*==\s*\d+\s*then/,           desc: 'generic: opcodeディスパッチ' },
    { re: /\{(\s*\d+\s*,){20,}/,                     desc: 'generic: 大規模数値テーブル' },
    { re: /\bbit\.bxor\b|\bbit\.band\b|\bbit32\./,   desc: 'generic: ビット演算' },
  ];

  let weredevScore = 0;
  let moonSecScore = 0;
  let luraphScore  = 0;

  for (const p of weredevPatterns) {
    if (p.re.test(code)) { hints.push(p.desc); weredevScore++; }
  }
  for (const p of moonSecPatterns) {
    if (p.re.test(code)) { hints.push(p.desc); moonSecScore++; }
  }
  for (const p of luraphPatterns) {
    if (p.re.test(code)) { hints.push(p.desc); luraphScore++; }
  }
  if (/return\s*\(function\s*\([^)]*\)/s.test(code)) hints.push('自己実行関数ラッパー');
  for (const p of genericPatterns) {
    if (p.re.test(code)) hints.push(p.desc);
  }

  const strings = [];
  const strPattern = /"([^"\\]{4,}(?:\\.[^"\\]*)*)"/g;
  let ms;
  while ((ms = strPattern.exec(code)) !== null) {
    if (ms[1].length > 4) strings.push(ms[1]);
  }
  if (strings.length > 0) hints.push(`${strings.length}件の文字列`);

  const isWereDev  = weredevScore >= 2;
  const isMoonSec  = moonSecScore >= 2;
  const isLuraph   = luraphScore  >= 1;
  const isVm       = hints.length >= 2;

  return { isVm, isWereDev, isMoonSec, isLuraph,
    weredevScore, moonSecScore, luraphScore,
    hints, strings: strings.slice(0, 50), method: 'vm_detect' };
}
function deobfuscateVmify(code) {
  const hints = [];
  if (/return\s*\(function\s*\([^)]*\)/s.test(code)) hints.push('VMラッパー検出');
  if (/\bInstructions\b|\bProto\b|\bupValues\b/i.test(code)) hints.push('Luaバイトコード構造を検出');
  const strings = [];
  const strPattern = /"([^"\\]{4,}(?:\\.[^"\\]*)*)"/g;
  let m;
  while ((m = strPattern.exec(code)) !== null) { if (m[1].length > 4) strings.push(m[1]); }
  if (strings.length > 0) hints.push(`${strings.length}件の文字列リテラルを抽出`);
  if (/\{(\s*\d+\s*,){8,}/.test(code)) hints.push('大規模バイトコードテーブルを検出');
  if (hints.length === 0) return { success: false, error: 'Vmifyパターンが検出されませんでした', method: 'vmify' };
  return { success: true, result: code, hints, strings: strings.slice(0, 50), warning: 'Vmify完全解読には動的実行を推奨', method: 'vmify' };
}

// ────────────────────────────────────────────────────────────────────────
//  #26/#27/#28/#29  vmHookBootstrap 強化版
// ────────────────────────────────────────────────────────────────────────
function isWeredevObfuscated(code) {
  if (!code) return false;
  // トリガー1: return(function(...) パターン
  if (/return\s*\(\s*function\s*\(/.test(code)) return true;
  // トリガー2: while true do + B[pc] + V レジスタ
  if (/while\s*(?:true|1)\s*do/i.test(code) && /\bB\s*\[/.test(code) && /\bV\s*\[/.test(code)) return true;
  // トリガー3: local l = B[pc] 形式
  if (/local\s+l\s*=\s*\w+\s*\[\s*\w+\s*\]/.test(code)) return true;
  return false;
}

// ── 項目 1: /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{/ で動的テーブル名取得 ──

module.exports = {
  loaderPatternDetected, vmDetector, deobfuscateVmify, isWeredevObfuscated,
};
