// core/detector.js
'use strict';

const { scoreLuaCode } = require('../utils/luaPrinter');

function loaderPatternDetected(code) {
  const p1 = /table\.concat\s*\(/.test(code) &&
              /string\.char\s*\(/.test(code) &&
              /\bloadstring\b|\bload\s*\(/.test(code);
  const p2 = /\bload\s*\(\s*\{/.test(code) ||
             (/\bload\s*\(/.test(code) && /\bstring\.char\b/.test(code));
  const p3 = /string\.char\s*\(\s*\d[\d\s,]{40,}\)/.test(code);
  const p4 = /table\.concat\s*\(\s*\{[\s\d,]+\}/.test(code);
  return p1 || p2 || p3 || p4;
}

// ────────────────────────────────────────────────────────────────────────
//  項目11: Weredevs VM 判定時に dynamic local table 名を
//  /local\s+([%w_]+)\s*=\s*{/ で動的取得する
// ────────────────────────────────────────────────────────────────────────
function extractDynamicLocalTableNames(code) {
  const names = [];
  const seen  = new Set();
  // local NAME = { ... } の形式で数値/文字列要素が多いものを候補とする
  const re = /local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const name = m[1];
    if (seen.has(name)) continue;
    seen.add(name);
    // テーブル本体を少し読んで数値/文字列要素があるか確認
    const snippet = code.substring(m.index + m[0].length, m.index + m[0].length + 200);
    const hasElements = /\d|"[^"]*"|'[^']*'/.test(snippet);
    if (hasElements) names.push(name);
  }
  return names;
}

function vmDetector(code) {
  const hints = [];

  // ── WereDev ─────────────────────────────────────────────────────────
  const weredevPatterns = [
    { re: /bytecode\s*\[\s*ip\s*\]/,                                  desc: 'WereDev: bytecode[ip]' },
    { re: /dispatch\s*\[\s*inst\s*\[\s*1\s*\]\s*\]/,                 desc: 'WereDev: dispatch[inst[1]]' },
    { re: /\bvm_loop\b/,                                              desc: 'WereDev: vm_loop' },
    { re: /while\s+true\s+do[\s\S]{0,400}bytecode\s*\[\s*ip\s*\]/i,  desc: 'WereDev: while-true+bytecode[ip]' },
    { re: /local\s+inst\s*=\s*bytecode\s*\[\s*ip\s*\]/,              desc: 'WereDev: local inst=bytecode[ip]' },
    { re: /inst\s*\[\s*1\s*\]/,                                       desc: 'WereDev: inst[1]' },
    { re: /ip\s*=\s*ip\s*\+\s*1/,                                    desc: 'WereDev: ip+1' },
    { re: /while\s*(?:true|1)\s*do[\s\S]{0,200}\bB\s*\[/,            desc: 'WereDev: while(true/1)+B[pc]' },
    { re: /local\s+l\s*=\s*\w+\s*\[\s*\w+\s*\]/,                    desc: 'WereDev: local l=B[pc]' },
    { re: /return\s*\(\s*function\s*\(/,                              desc: 'WereDev: return(function' },
  ];

  // ── MoonSec ─────────────────────────────────────────────────────────
  const moonSecPatterns = [
    { re: /MoonSec/,                                                  desc: 'MoonSec: MoonSec識別子' },
    { re: /MSVM/,                                                     desc: 'MoonSec: MSVM' },
    { re: /_ENV\s*\[.+\]/,                                            desc: 'MoonSec: _ENV[key]アクセス' },
    { re: /dispatch\s*\[opcode\]/,                                    desc: 'MoonSec: dispatch[opcode]' },
    { re: /stk\s*\[top\]|stk\s*\[top\s*-/,                          desc: 'MoonSec: stack top操作' },
  ];

  // ── Luraph ──────────────────────────────────────────────────────────
  const luraphPatterns = [
    { re: /LPH_String/,                                               desc: 'Luraph: LPH_String' },
    { re: /LPH_GetEnv/,                                               desc: 'Luraph: LPH_GetEnv' },
    { re: /LPH_JIT/,                                                  desc: 'Luraph: LPH_JIT' },
    { re: /\bLPH\b/,                                                  desc: 'Luraph: LPH識別子' },
  ];

  // ── 汎用VM ──────────────────────────────────────────────────────────
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

  const isWereDev = weredevScore >= 2;
  const isMoonSec = moonSecScore >= 2;
  const isLuraph  = luraphScore  >= 1;
  const isVm      = hints.length >= 2;

  // 項目11: Weredevs VM 検出時に dynamic local table 名を取得
  const dynamicTableNames = (isWereDev || isVm) ? extractDynamicLocalTableNames(code) : [];

  return {
    isVm, isWereDev, isMoonSec, isLuraph,
    weredevScore, moonSecScore, luraphScore,
    hints, strings: strings.slice(0, 50),
    dynamicTableNames,   // 追加: 動的テーブル名リスト
    method: 'vm_detect',
  };
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

function isWeredevObfuscated(code) {
  if (!code) return false;
  if (/return\s*\(\s*function\s*\(/.test(code)) return true;
  if (/while\s*(?:true|1)\s*do/i.test(code) && /\bB\s*\[/.test(code) && /\bV\s*\[/.test(code)) return true;
  if (/local\s+l\s*=\s*\w+\s*\[\s*\w+\s*\]/.test(code)) return true;
  return false;
}

module.exports = {
  loaderPatternDetected, vmDetector, deobfuscateVmify, isWeredevObfuscated,
  extractDynamicLocalTableNames,
};
