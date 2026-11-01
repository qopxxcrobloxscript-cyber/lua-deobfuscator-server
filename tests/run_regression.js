#!/usr/bin/env node
/**
 * VM難読化(vm_obfuscator.lua)の自動回帰テスト。
 *
 * tests/fixtures/ 配下の各Luaスクリプトについて、
 *   1. そのまま素のLuaで実行した出力(ベースライン)を取得する
 *   2. 複数のシード × 複数のstrength(1〜15)の組み合わせでVM難読化し、
 *      難読化後のコードを実行する
 *   3. 出力がベースラインと完全一致するかを確認する
 *
 * vm_obfuscator.lua に手を加えたときに「難読化前後で動作が変わっていないか」
 * を機械的に保証するための安全網。CIや `npm test` から実行できる。
 *
 * 使い方:
 *   node tests/run_regression.js
 *   node tests/run_regression.js --quick   (シード/strengthの組み合わせを間引いて高速実行)
 *   node tests/run_regression.js --seeds=1,42,999 --strengths=1,5,15
 */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const VM_OBFUSCATOR = path.join(ROOT, "vm_obfuscator.lua");
const FIXTURES_DIR = path.join(__dirname, "fixtures");
const TMP_DIR = path.join(__dirname, ".tmp");

// ──────────────────────────────────────────────────────────────
// Lua実行バイナリの検出(server.jsのcheckLuaAvailable()と同じ優先順位)
// ──────────────────────────────────────────────────────────────
function findLuaBinary() {
  const candidates = ["lua5.1", "lua", "luajit", "lua5.4", "lua5.3"];
  for (const bin of candidates) {
    try {
      execFileSync(bin, ["-v"], { timeout: 3000, stdio: "pipe" });
      return bin;
    } catch (_) {
      /* try next */
    }
  }
  return null;
}

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { quick: false, seeds: null, strengths: null };
  for (const a of args) {
    if (a === "--quick") opts.quick = true;
    else if (a.startsWith("--seeds=")) opts.seeds = a.slice(8).split(",").map(Number);
    else if (a.startsWith("--strengths=")) opts.strengths = a.slice(12).split(",").map(Number);
  }
  return opts;
}

function runLua(luaBin, scriptPath, args = []) {
  return execFileSync(luaBin, [scriptPath, ...args], {
    encoding: "utf8",
    timeout: 20000,
  });
}

function main() {
  const opts = parseArgs();
  const luaBin = findLuaBinary();
  if (!luaBin) {
    console.error("FATAL: Luaインタプリタが見つかりません(lua5.1 / lua / luajit のいずれも実行できません)");
    process.exit(2);
  }
  console.log(`Lua binary: ${luaBin}`);

  if (!fs.existsSync(VM_OBFUSCATOR)) {
    console.error(`FATAL: vm_obfuscator.lua が見つかりません: ${VM_OBFUSCATOR}`);
    process.exit(2);
  }

  fs.mkdirSync(TMP_DIR, { recursive: true });

  const seeds = opts.seeds || (opts.quick ? [1, 42, 999] : [1, 42, 999, 12345, 271828, 777777]);
  const strengths = opts.strengths || (opts.quick ? [1, 8, 15] : [1, 3, 5, 7, 9, 11, 13, 15]);

  const fixtures = fs
    .readdirSync(FIXTURES_DIR)
    .filter((f) => f.endsWith(".lua"))
    .sort();

  if (fixtures.length === 0) {
    console.error(`FATAL: テストスクリプトが見つかりません: ${FIXTURES_DIR}`);
    process.exit(2);
  }

  let total = 0;
  let failed = 0;
  const failures = [];

  for (const fixture of fixtures) {
    const fixturePath = path.join(FIXTURES_DIR, fixture);
    let baseline;
    try {
      baseline = runLua(luaBin, fixturePath);
    } catch (e) {
      console.error(`SKIP ${fixture}: ベースライン実行に失敗 (${e.message})`);
      continue;
    }

    for (const seed of seeds) {
      for (const strength of strengths) {
        total++;
        const outPath = path.join(TMP_DIR, `out_${process.pid}.lua`);
        try {
          execFileSync(
            luaBin,
            [VM_OBFUSCATOR, fixturePath, "--out", outPath, "--seed", String(seed), "--strength", String(strength)],
            { timeout: 20000, stdio: "pipe" }
          );
        } catch (e) {
          failed++;
          failures.push({ fixture, seed, strength, stage: "generate", detail: e.message });
          continue;
        }

        let output;
        try {
          output = runLua(luaBin, outPath);
        } catch (e) {
          failed++;
          failures.push({ fixture, seed, strength, stage: "execute", detail: e.message });
          continue;
        }

        if (output !== baseline) {
          failed++;
          failures.push({
            fixture,
            seed,
            strength,
            stage: "mismatch",
            detail: `expected:\n${baseline}\n---\nactual:\n${output}`,
          });
        }
      }
    }
  }

  // 後片付け
  try {
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
  } catch (_) {}

  console.log("");
  console.log(`結果: ${total - failed}/${total} passed`);

  if (failed > 0) {
    console.log("");
    console.log("── 失敗一覧 (最大20件) ──");
    for (const f of failures.slice(0, 20)) {
      console.log(`[FAIL] ${f.fixture} seed=${f.seed} strength=${f.strength} stage=${f.stage}`);
      console.log(`  ${f.detail.split("\n").slice(0, 6).join("\n  ")}`);
    }
    process.exit(1);
  } else {
    console.log("全テストが成功しました。");
    process.exit(0);
  }
}

main();
