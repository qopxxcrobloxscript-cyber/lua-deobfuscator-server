// vm/weredevs/emulator.js
'use strict';

// ════════════════════════════════════════════════════════════════════════
//  WeredevVM — Weredevs 難読化 VM のソフトウェアエミュレータ
//
//  役割:
//    静的解析 (extractor → interpreterParser → opcodeMap) で得た
//    bytecode / constants を受け取り、実際に命令をステップ実行して
//    execution trace を生成する。
//    trace は decompiler に渡され疑似 Lua コードへ変換される。
//
//  state:
//    ip          : number   — プログラムカウンタ (0-indexed)
//    registers   : object   — Lua レジスタ (R[0]〜R[255])
//    stack       : array    — call stack フレーム
//    upvalues    : object   — upvalue テーブル
//    globals     : object   — _G 相当のグローバル
//    bytecode    : array    — 命令配列 [{op,a,b,c,bx,sbx}, ...]
//    constants   : array    — 定数プール [{type,value}, ...]
//    callLog     : array    — CALL 命令ログ
//    jumpLog     : array    — JMP/条件分岐ログ
// ════════════════════════════════════════════════════════════════════════

const MAX_STEPS    = 200_000;   // 無限ループ防止
const MAX_TRACE    = 50_000;    // trace 最大保持数

// ────────────────────────────────────────────────────────────────────────
//  WeredevVM クラス
// ────────────────────────────────────────────────────────────────────────
class WeredevVM {
  /**
   * @param {Array<{op:string|number, a:number, b:number, c:number, bx?:number, sbx?:number}>} bytecode
   * @param {Array<{type:string, value:*}>} constants
   * @param {object} [options]
   * @param {number}  [options.maxSteps=200000]
   * @param {number}  [options.maxTrace=50000]
   * @param {object}  [options.globals]   — 初期グローバル (デフォルトは安全な stub)
   * @param {boolean} [options.strict]    — 未知 opcode で throw するか (default: false)
   */
  constructor(bytecode, constants, options = {}) {
    this.bytecode  = bytecode  || [];
    this.constants = constants || [];
    this.ip        = 0;

    // レジスタ: Lua5.1 は最大 255 レジスタ
    this.registers = Object.create(null);

    // call stack: { returnIp, baseReg, nResults }
    this.stack     = [];

    // upvalue テーブル (簡易: フラット配列)
    this.upvalues  = [];

    // globals stub — 実際の Lua 関数は呼べないのでログのみ
    this.globals   = Object.assign(Object.create(null), options.globals || _defaultGlobals());

    // オプション
    this.maxSteps  = options.maxSteps || MAX_STEPS;
    this.maxTrace  = options.maxTrace || MAX_TRACE;
    this.strict    = options.strict   || false;

    // ログ
    this.callLog   = [];
    this.jumpLog   = [];
    this._steps    = 0;
    this._halted   = false;
    this._haltReason = null;
  }

  // ── 定数参照ヘルパー ───────────────────────────────────────────────
  /** RK(x): x >= 256 なら定数プール、そうでなければレジスタ */
  rk(x) {
    if (x === null || x === undefined) return null;
    if (x >= 256) {
      const c = this.constants[x - 256];
      return c !== undefined ? c.value : null;
    }
    return this.registers[x] !== undefined ? this.registers[x] : null;
  }

  /** K(x): 定数プール直引き (0-indexed) */
  k(x) {
    const c = this.constants[x];
    return c !== undefined ? c.value : null;
  }

  /** R(x): レジスタ読み取り */
  r(x) {
    return this.registers[x] !== undefined ? this.registers[x] : null;
  }

  /** R(x) = v: レジスタ書き込み */
  setR(x, v) {
    this.registers[x] = v;
  }

  // ── 1命令ステップ実行 ─────────────────────────────────────────────
  /**
   * @returns {'ok'|'halt'|'return'|'error'}
   */
  step() {
    if (this._halted) return 'halt';
    if (this.ip >= this.bytecode.length) {
      this._halt('ip_out_of_range');
      return 'halt';
    }
    if (++this._steps > this.maxSteps) {
      this._halt('max_steps');
      return 'halt';
    }

    const instr = this.bytecode[this.ip];
    if (!instr) { this._halt('null_instruction'); return 'halt'; }

    // op は文字列 ("LOADK" など) または数値どちらも許容
    const op = typeof instr.op === 'string'
      ? instr.op.toUpperCase()
      : _numToOpName(instr.op);

    const A   = instr.a  !== undefined ? instr.a   : instr.A;
    const B   = instr.b  !== undefined ? instr.b   : instr.B;
    const C   = instr.c  !== undefined ? instr.c   : instr.C;
    const Bx  = instr.bx !== undefined ? instr.bx  : (instr.Bx  !== undefined ? instr.Bx  : ((B << 9) | C));
    const sBx = instr.sbx!== undefined ? instr.sbx : (instr.sBx !== undefined ? instr.sBx : Bx - 131071);

    switch (op) {
      // ── データ転送 ─────────────────────────────────────────────────
      case 'MOVE':
        this.setR(A, this.r(B));
        break;

      case 'LOADK':
        // B: 定数インデックス (Bx として使う)
        this.setR(A, this.k(Bx !== undefined ? Bx : B));
        break;

      case 'LOADBOOL':
        this.setR(A, B !== 0);
        if (C !== 0) this.ip++;      // skip next
        break;

      case 'LOADNIL':
        for (let i = A; i <= B; i++) this.setR(i, null);
        break;

      // ── upvalue / global ──────────────────────────────────────────
      case 'GETUPVAL':
        this.setR(A, this.upvalues[B] !== undefined ? this.upvalues[B] : null);
        break;

      case 'SETUPVAL':
        this.upvalues[B] = this.r(A);
        break;

      case 'GETGLOBAL': {
        const gname = this.k(Bx !== undefined ? Bx : B);
        this.setR(A, this.globals[gname] !== undefined ? this.globals[gname] : null);
        break;
      }

      case 'SETGLOBAL': {
        const gname2 = this.k(Bx !== undefined ? Bx : B);
        this.globals[gname2] = this.r(A);
        break;
      }

      // ── テーブル操作 ──────────────────────────────────────────────
      case 'NEWTABLE':
        this.setR(A, Object.create(null));
        break;

      case 'GETTABLE': {
        const tbl = this.r(B);
        const key = this.rk(C);
        this.setR(A, _tableGet(tbl, key));
        break;
      }

      case 'SETTABLE': {
        const tbl2 = this.r(A);
        const key2 = this.rk(B);
        const val  = this.rk(C);
        _tableSet(tbl2, key2, val);
        break;
      }

      case 'SELF': {
        // R(A+1) = R(B); R(A) = R(B)[RK(C)]
        const self = this.r(B);
        this.setR(A + 1, self);
        this.setR(A, _tableGet(self, this.rk(C)));
        break;
      }

      case 'SETLIST': {
        // R(A)[(C-1)*FPF + i] = R(A+i), i in 1..B
        const base = A;
        const n    = B || (this.bytecode.length - this.ip);  // B=0: 可変長
        const offset_ = ((C - 1) * 50);
        const tbl3 = this.r(base);
        if (tbl3) {
          for (let i = 1; i <= n; i++) {
            tbl3[offset_ + i] = this.r(base + i);
          }
        }
        break;
      }

      // ── 算術 ──────────────────────────────────────────────────────
      case 'ADD': this.setR(A, _arith(this.rk(B), this.rk(C), '+')); break;
      case 'SUB': this.setR(A, _arith(this.rk(B), this.rk(C), '-')); break;
      case 'MUL': this.setR(A, _arith(this.rk(B), this.rk(C), '*')); break;
      case 'DIV': this.setR(A, _arith(this.rk(B), this.rk(C), '/')); break;
      case 'MOD': this.setR(A, _arith(this.rk(B), this.rk(C), '%')); break;
      case 'POW': this.setR(A, _arith(this.rk(B), this.rk(C), '^')); break;
      case 'UNM': this.setR(A, _arith(this.r(B),  0,           'neg')); break;
      case 'NOT': this.setR(A, !_luaTruth(this.r(B))); break;
      case 'LEN': this.setR(A, _luaLen(this.r(B))); break;

      case 'CONCAT': {
        let s = '';
        for (let i = B; i <= C; i++) {
          const v = this.r(i);
          s += (v !== null && v !== undefined) ? String(v) : '';
        }
        this.setR(A, s);
        break;
      }

      // ── 比較・条件分岐 ────────────────────────────────────────────
      case 'EQ': {
        const eq = _luaEq(this.rk(B), this.rk(C));
        if ((A !== 0) !== eq) this.ip++;   // skip next (JMP)
        this.jumpLog.push({ ip: this.ip, op: 'EQ', A, B, C, result: eq });
        break;
      }
      case 'LT': {
        const lt = _luaLt(this.rk(B), this.rk(C));
        if ((A !== 0) !== lt) this.ip++;
        this.jumpLog.push({ ip: this.ip, op: 'LT', A, B, C, result: lt });
        break;
      }
      case 'LE': {
        const le = _luaLe(this.rk(B), this.rk(C));
        if ((A !== 0) !== le) this.ip++;
        this.jumpLog.push({ ip: this.ip, op: 'LE', A, B, C, result: le });
        break;
      }
      case 'TEST': {
        const tv = _luaTruth(this.r(A));
        if (tv === (C === 0)) this.ip++;   // skip if条件不一致
        this.jumpLog.push({ ip: this.ip, op: 'TEST', A, C, result: tv });
        break;
      }
      case 'TESTSET': {
        const tv2 = _luaTruth(this.r(B));
        if (tv2 !== (C !== 0)) { this.ip++; }
        else { this.setR(A, this.r(B)); }
        this.jumpLog.push({ ip: this.ip, op: 'TESTSET', A, B, C, result: tv2 });
        break;
      }

      // ── ジャンプ ──────────────────────────────────────────────────
      case 'JMP': {
        const target = this.ip + 1 + sBx;
        this.jumpLog.push({ ip: this.ip, op: 'JMP', offset: sBx, target });
        this.ip = target;
        return 'ok';   // ip++ しない
      }

      // ── ループ ────────────────────────────────────────────────────
      case 'FORPREP': {
        // R(A) -= R(A+2)
        const init  = _toNumber(this.r(A));
        const step_ = _toNumber(this.r(A + 2));
        this.setR(A, init - step_);
        this.ip += sBx + 1;
        return 'ok';
      }
      case 'FORLOOP': {
        const idx   = _toNumber(this.r(A)) + _toNumber(this.r(A + 2));
        const limit = _toNumber(this.r(A + 1));
        const step_ = _toNumber(this.r(A + 2));
        this.setR(A, idx);
        const cont = step_ > 0 ? idx <= limit : idx >= limit;
        if (cont) {
          this.setR(A + 3, idx);
          this.ip += sBx + 1;
          return 'ok';
        }
        break;
      }
      case 'TFORLOOP': {
        // Generic for: R(A+3), ..., R(A+2+C) = R(A)(R(A+1), R(A+2))
        // 実際の関数呼び出しは stub
        const iterResult = _callStub(this.r(A), [this.r(A + 1), this.r(A + 2)], this.callLog, this.ip);
        if (iterResult !== null && iterResult !== undefined) {
          this.setR(A + 3, iterResult);
          this.setR(A + 2, iterResult);
          // jump back
        } else {
          this.ip++;  // skip JMP
        }
        break;
      }

      // ── 関数呼び出し ──────────────────────────────────────────────
      case 'CALL': {
        // B-1: 引数数, C-1: 戻り値数 (0=可変)
        const fn       = this.r(A);
        const nArgs    = B === 0 ? 0 : B - 1;
        const args_    = [];
        for (let i = 1; i <= nArgs; i++) args_.push(this.r(A + i));

        const callEntry = {
          ip:     this.ip,
          fnReg:  A,
          fnName: _describeValue(fn),
          args:   args_.map(_describeValue),
          nArgs,
          nResults: C - 1,
        };
        this.callLog.push(callEntry);

        // stub 実行
        const results = _callStub(fn, args_, this.callLog, this.ip);
        const nRet    = C === 0 ? 1 : C - 1;
        if (results !== null && results !== undefined) {
          const arr = Array.isArray(results) ? results : [results];
          for (let i = 0; i < nRet; i++) {
            this.setR(A + i, arr[i] !== undefined ? arr[i] : null);
          }
        }
        break;
      }

      case 'TAILCALL': {
        const fn2    = this.r(A);
        const nArgs2 = B === 0 ? 0 : B - 1;
        const args2  = [];
        for (let i = 1; i <= nArgs2; i++) args2.push(this.r(A + i));
        this.callLog.push({ ip: this.ip, fnReg: A, fnName: _describeValue(fn2), args: args2.map(_describeValue), isTail: true });
        this._halt('tailcall');
        return 'return';
      }

      case 'RETURN': {
        const nVals = B === 0 ? 1 : B - 1;
        const retVals = [];
        for (let i = 0; i < nVals; i++) retVals.push(this.r(A + i));
        this._returnValues = retVals;
        this._halt('return');
        return 'return';
      }

      // ── クロージャ ────────────────────────────────────────────────
      case 'CLOSURE':
        // proto index = Bx. 実行はしないが記録
        this.setR(A, { _type: 'closure', protoIdx: Bx !== undefined ? Bx : B });
        break;

      case 'CLOSE':
        // upvalue のクローズ — 静的解析では無視でOK
        break;

      case 'VARARG': {
        // 可変引数を R(A)〜R(A+B-2) にセット (stub: null)
        const nVarArg = B === 0 ? 1 : B - 1;
        for (let i = 0; i < nVarArg; i++) this.setR(A + i, null);
        break;
      }

      default:
        if (this.strict) throw new Error(`Unknown opcode: ${op}`);
        // 未知 opcode はスキップ (静的 trace 用)
        break;
    }

    this.ip++;
    return 'ok';
  }

  // ── halt ───────────────────────────────────────────────────────────
  _halt(reason) {
    this._halted    = true;
    this._haltReason = reason;
  }

  // ── 全命令実行して trace を返す ────────────────────────────────────
  /**
   * @returns {{
   *   trace: Array<{ip:number, op:string, a:number, b:number, c:number,
   *                 registers:object, step:number}>,
   *   callLog: Array,
   *   jumpLog: Array,
   *   haltReason: string,
   *   steps: number,
   *   returnValues: Array
   * }}
   */
  run() {
    const trace = [];

    while (!this._halted && this.ip < this.bytecode.length) {
      const instr = this.bytecode[this.ip];
      if (!instr) break;

      // trace エントリを push (step() 実行前のスナップショット)
      if (trace.length < this.maxTrace) {
        trace.push({
          ip:        this.ip,
          op:        typeof instr.op === 'string' ? instr.op.toUpperCase() : _numToOpName(instr.op),
          a:         instr.a !== undefined ? instr.a : instr.A,
          b:         instr.b !== undefined ? instr.b : instr.B,
          c:         instr.c !== undefined ? instr.c : instr.C,
          registers: _snapshotRegs(this.registers),
          step:      this._steps,
        });
      }

      const status = this.step();
      if (status === 'halt' || status === 'return') break;
    }

    return {
      trace,
      callLog:      this.callLog,
      jumpLog:      this.jumpLog,
      haltReason:   this._haltReason || (this.ip >= this.bytecode.length ? 'end_of_bytecode' : 'unknown'),
      steps:        this._steps,
      returnValues: this._returnValues || [],
    };
  }
}

// ════════════════════════════════════════════════════════════════════════
//  bytecode / constants パーサー
//  extractor.js が返す raw データを WeredevVM が受け取れる形式に変換する
// ════════════════════════════════════════════════════════════════════════

/**
 * extractWeredevConstPool の結果 (pools オブジェクト) から
 * constants 配列 [{type, value}] を構築する。
 *
 * アクセサ Z(i) = R[i - offset] の offset を考慮して
 * 0-indexed の定数配列に正規化する。
 *
 * @param {object} constPools  — extractWeredevConstPool の返り値
 * @param {object} accessors   — extractWeredevZAccessor の返り値
 * @returns {Array<{type:string, value:*}>}
 */
function buildConstantsFromPools(constPools, accessors) {
  // アクセサが存在する場合、そのプールを優先
  const accList = Object.values(accessors || {});
  if (accList.length > 0) {
    const acc  = accList[0];
    const pool = constPools[acc.poolName];
    if (pool && pool.elements) return pool.elements;
  }
  // アクセサなし: プール全体を連結
  const all = [];
  for (const pool of Object.values(constPools)) {
    if (pool.elements) all.push(...pool.elements);
  }
  return all;
}

/**
 * dispatchBlocks (extractWeredevDispatchLoop の返り値内)から
 * bytecode 命令配列 [{op, a, b, c}] を構築する。
 *
 * Weredev は dispatch ループ内の if-chain で opcode をシミュレートする。
 * assignWeredevOpcodes でナンバリングされた blocks から
 * 命令列を再構成する。
 *
 * @param {Array}  numberedBlocks  — assignWeredevOpcodes の返り値
 * @param {object} ctx             — detectWeredevContext の返り値
 * @returns {Array<{op:string|number, a:number|null, b:number|null, c:number|null}>}
 */
function buildBytecodeFromBlocks(numberedBlocks, ctx) {
  const instructions = [];
  for (const block of numberedBlocks) {
    // interpreterParser.js の extractWeredevOperands でオペランドを取得済み前提
    // ここでは block.opName / block.A / block.B / block.C を使う
    instructions.push({
      op:  block.opName || `OP_${block.estimatedOpcode}`,
      a:   block.A !== undefined ? block.A : null,
      b:   block.B !== undefined ? block.B : null,
      c:   block.C !== undefined ? block.C : null,
      _threshold:      block.threshold,
      _estimatedOpcode: block.estimatedOpcode,
    });
  }
  return instructions;
}

// ════════════════════════════════════════════════════════════════════════
//  trace → decompiler 用エントリ変換
//  WeredevVM.run() の trace を decompiler.js の vmDecompiler が
//  受け取れる形式 (ip / op / arg1 / arg2 / arg3) に変換する
// ════════════════════════════════════════════════════════════════════════
/**
 * @param {Array} trace  — WeredevVM.run().trace
 * @returns {Array<{ip:number, op:string|number, arg1:*, arg2:*, arg3:*}>}
 */
function traceToVmTrace(trace) {
  return trace.map(e => ({
    ip:   e.ip,
    op:   e.op,
    arg1: e.a,
    arg2: e.b,
    arg3: e.c,
    // weredev 形式でも使えるよう l/A/B/C も付与
    l:    e.op,
    pc:   e.ip,
    A:    e.a,
    B:    e.b,
    C:    e.c,
    regs: e.registers,
  }));
}

// ════════════════════════════════════════════════════════════════════════
//  メインエントリ: emulateWeredevVM
//  extractor → interpreterParser → opcodeMap の出力を受けて
//  emulator を実行し trace を返す
// ════════════════════════════════════════════════════════════════════════
/**
 * @param {object} params
 * @param {object} params.constPools    — extractWeredevConstPool の返り値
 * @param {object} params.accessors     — extractWeredevZAccessor の返り値
 * @param {Array}  params.dispatchLoops — extractWeredevDispatchLoop の返り値
 * @param {object} params.ctx           — detectWeredevContext の返り値
 * @param {Array}  params.numberedBlocks — assignWeredevOpcodes の返り値 (オプション)
 * @param {object} [params.options]     — WeredevVM オプション
 * @returns {{
 *   success: boolean,
 *   trace: Array,
 *   vmTrace: Array,        ← decompiler に直接渡せる形式
 *   callLog: Array,
 *   jumpLog: Array,
 *   haltReason: string,
 *   steps: number,
 *   method: string,
 *   error: string|null
 * }}
 */
function emulateWeredevVM(params) {
  const { constPools, accessors, dispatchLoops, ctx, numberedBlocks, options } = params;

  try {
    // 定数配列を構築
    const constants = buildConstantsFromPools(constPools || {}, accessors || {});

    // bytecode を構築
    // numberedBlocks が直接渡された場合はそれを使う
    // なければ dispatchLoops の最初のループから生成
    let instructions = [];
    if (numberedBlocks && numberedBlocks.length > 0) {
      instructions = buildBytecodeFromBlocks(numberedBlocks, ctx);
    } else if (dispatchLoops && dispatchLoops.length > 0) {
      // 最大ブロック数のループを採用
      const bestLoop = dispatchLoops.reduce((a, b) =>
        b.blockCount > a.blockCount ? b : a
      );
      if (bestLoop.dispatchBlocks && bestLoop.dispatchBlocks.length > 0) {
        // interpreterParser の extractWeredevOperands を適用して A/B/C を補完
        const { extractWeredevOperands } = require('./interpreterParser');
        const { _inferOpNameFromOperands } = require('./opcodeMap');
        const { assignWeredevOpcodes }     = require('./opcodeMap');

        const nbBlocks = assignWeredevOpcodes(bestLoop.dispatchBlocks);
        const enriched = nbBlocks.map(block => {
          const operands    = extractWeredevOperands(block.body, ctx);
          const detectedOp  = _inferOpNameFromOperands(operands, block.body, ctx);
          return {
            ...block,
            opName: detectedOp,
            A: operands.A,
            B: operands.B,
            C: operands.C,
          };
        });
        instructions = buildBytecodeFromBlocks(enriched, ctx);
      }
    }

    if (instructions.length === 0) {
      return {
        success: false,
        trace: [], vmTrace: [], callLog: [], jumpLog: [],
        haltReason: 'no_instructions',
        steps: 0, method: 'weredev_emulate',
        error: 'bytecode命令が0件です。dispatchLoopsまたはnumberedBlocksを確認してください。',
      };
    }

    // VM 実行
    const vm      = new WeredevVM(instructions, constants, options || {});
    const result  = vm.run();

    return {
      success:     true,
      trace:       result.trace,
      vmTrace:     traceToVmTrace(result.trace),   // decompiler 互換
      callLog:     result.callLog,
      jumpLog:     result.jumpLog,
      haltReason:  result.haltReason,
      steps:       result.steps,
      returnValues: result.returnValues,
      method:      'weredev_emulate',
      error:       null,
      // デバッグ情報
      _constCount: constants.length,
      _instrCount: instructions.length,
    };

  } catch (e) {
    return {
      success: false,
      trace: [], vmTrace: [], callLog: [], jumpLog: [],
      haltReason: 'exception',
      steps: 0, method: 'weredev_emulate',
      error: 'エミュレータ例外: ' + e.message,
    };
  }
}

// ════════════════════════════════════════════════════════════════════════
//  内部ユーティリティ
// ════════════════════════════════════════════════════════════════════════

/** Lua5.1 opcode 番号 → 名前 */
function _numToOpName(n) {
  const MAP = [
    'MOVE','LOADK','LOADBOOL','LOADNIL','GETUPVAL',
    'GETGLOBAL','GETTABLE','SETGLOBAL','SETUPVAL','SETTABLE',
    'NEWTABLE','SELF','ADD','SUB','MUL',
    'DIV','MOD','POW','UNM','NOT',
    'LEN','CONCAT','JMP','EQ','LT',
    'LE','TEST','TESTSET','CALL','TAILCALL',
    'RETURN','FORLOOP','FORPREP','TFORLOOP','SETLIST',
    'CLOSE','CLOSURE','VARARG',
  ];
  return MAP[n] || `OP_${n}`;
}

/** Lua 真偽値判定 (nil と false のみ偽) */
function _luaTruth(v) {
  return v !== null && v !== undefined && v !== false;
}

/** Lua == 比較 */
function _luaEq(a, b) {
  if (a === null && b === null)     return true;
  if (typeof a !== typeof b)        return false;
  return a === b;
}

/** Lua < 比較 */
function _luaLt(a, b) {
  if (typeof a === 'number' && typeof b === 'number') return a < b;
  if (typeof a === 'string' && typeof b === 'string') return a < b;
  return false;
}

/** Lua <= 比較 */
function _luaLe(a, b) {
  return _luaLt(a, b) || _luaEq(a, b);
}

/** Lua 算術演算 */
function _arith(a, b, op) {
  const na = _toNumber(a), nb = _toNumber(b);
  if (op === 'neg') return typeof na === 'number' ? -na : null;
  if (na === null || nb === null) return null;
  switch (op) {
    case '+': return na + nb;
    case '-': return na - nb;
    case '*': return na * nb;
    case '/': return nb !== 0 ? na / nb : null;
    case '%': return nb !== 0 ? ((na % nb) + nb) % nb : null;
    case '^': return Math.pow(na, nb);
    default:  return null;
  }
}

function _toNumber(v) {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') { const n = Number(v); return isNaN(n) ? null : n; }
  return null;
}

/** Lua # 演算子 (長さ) */
function _luaLen(v) {
  if (typeof v === 'string') return v.length;
  if (v && typeof v === 'object') {
    // 配列部分の長さ (Lua 仕様: t[1]..t[n] が nil でない最大 n)
    let n = 0;
    while (v[n + 1] !== undefined && v[n + 1] !== null) n++;
    return n;
  }
  return 0;
}

/** テーブル読み取り (null 安全) */
function _tableGet(tbl, key) {
  if (!tbl || typeof tbl !== 'object') return null;
  if (key === null || key === undefined) return null;
  // Lua は 1-indexed 配列を使うため数値キーをそのまま使用
  return tbl[key] !== undefined ? tbl[key] : null;
}

/** テーブル書き込み (null 安全) */
function _tableSet(tbl, key, val) {
  if (!tbl || typeof tbl !== 'object') return;
  if (key === null || key === undefined) return;
  tbl[key] = val;
}

/** 値を短い説明文字列に変換 (callLog 用) */
function _describeValue(v) {
  if (v === null || v === undefined) return 'nil';
  if (typeof v === 'boolean') return String(v);
  if (typeof v === 'number')  return String(v);
  if (typeof v === 'string')  return `"${v.substring(0, 40).replace(/\n/g, '\\n')}"`;
  if (typeof v === 'function') return '<native>';
  if (v && v._type === 'closure') return `<closure#${v.protoIdx}>`;
  if (typeof v === 'object')  return '<table>';
  return String(v);
}

/** 関数呼び出し stub — 実際には実行しない, ログのみ */
function _callStub(fn, args, callLog, ip) {
  if (typeof fn === 'function') {
    // 組み込み関数 (globals に登録された stub) は実行
    try { return fn(...args); } catch { return null; }
  }
  // closure や unknown は null を返す
  return null;
}

/** レジスタのスナップショット (最初の 16 個のみ) */
function _snapshotRegs(regs) {
  const snap = Object.create(null);
  for (let i = 0; i < 16; i++) {
    if (regs[i] !== undefined) snap[i] = regs[i];
  }
  return snap;
}

/** デフォルトグローバル stub テーブル */
function _defaultGlobals() {
  return {
    print:         (...a) => null,
    tostring:      (v)    => v !== null && v !== undefined ? String(v) : 'nil',
    tonumber:      (v, b) => { const n = Number(v); return isNaN(n) ? null : n; },
    type:          (v)    => v === null ? 'nil' : typeof v === 'object' ? 'table' : typeof v,
    ipairs:        (t)    => null,
    pairs:         (t)    => null,
    unpack:        (t)    => null,
    select:        (...a) => null,
    error:         (msg)  => null,
    pcall:         (f, ...a) => [false, null],
    rawget:        (t, k) => (t && t[k]) || null,
    rawset:        (t, k, v) => { if (t) t[k] = v; return t; },
    rawequal:      (a, b) => a === b,
    setmetatable:  (t)    => t,
    getmetatable:  (t)    => null,
    require:       (m)    => null,
    assert:        (v, m) => v || null,
    math: {
      floor: Math.floor, ceil: Math.ceil, abs: Math.abs,
      sqrt: Math.sqrt, max: Math.max, min: Math.min,
      random: () => 0, huge: Infinity, pi: Math.PI,
    },
    string: {
      char:    (...a) => a.map(n => String.fromCharCode(n)).join(''),
      byte:    (s, i) => typeof s === 'string' ? s.charCodeAt((i || 1) - 1) : null,
      len:     (s)    => typeof s === 'string' ? s.length : 0,
      sub:     (s, i, j) => typeof s === 'string' ? s.slice(i - 1, j) : '',
      rep:     (s, n) => typeof s === 'string' ? s.repeat(n) : '',
      reverse: (s)    => typeof s === 'string' ? s.split('').reverse().join('') : '',
      format:  (fmt)  => String(fmt),
      find:    (s, p) => null,
      gsub:    (s)    => [s, 0],
      lower:   (s)    => typeof s === 'string' ? s.toLowerCase() : s,
      upper:   (s)    => typeof s === 'string' ? s.toUpperCase() : s,
    },
    table: {
      insert: (t, v) => { if (t) t[Object.keys(t).length + 1] = v; },
      remove: (t)    => null,
      concat: (t, s) => null,
      sort:   (t)    => null,
    },
    bit32: {
      bxor:   (a, b) => (a ^ b) >>> 0,
      band:   (a, b) => (a & b) >>> 0,
      bor:    (a, b) => (a | b) >>> 0,
      bnot:   (a)    => (~a)    >>> 0,
      lshift: (a, n) => (a << n) >>> 0,
      rshift: (a, n) => (a >>> n),
    },
  };
}

// ════════════════════════════════════════════════════════════════════════
//  exports
// ════════════════════════════════════════════════════════════════════════
module.exports = {
  WeredevVM,
  emulateWeredevVM,
  buildConstantsFromPools,
  buildBytecodeFromBlocks,
  traceToVmTrace,
};
