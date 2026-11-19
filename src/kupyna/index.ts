import { abytes, aexists, ahash, aoutput, clean, createHasher, createView, type CHash, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { HashMD } from "@noble/hashes/_md.js";
import { column } from "../kalyna/index.js";
import { _U32 } from "../utils.js";

const R_LO = 0xF0F0F0F3,
    R_HI = 0x00F0F0F0;

abstract class Kupyna<T extends Kupyna<T>> extends HashMD<T> {
    private readonly rounds: number;
    private readonly stSize: number;
    private readonly offs: number[];
    protected s: Uint32Array;

    private readonly m: Uint32Array;
    private readonly ap: Uint32Array;
    private readonly aq: Uint32Array;
    private readonly tmp: Uint32Array;

    constructor(blockLen: number) {
        super(blockLen, blockLen / 2, 12, true);
        this.stSize = blockLen >>> 3;
        this.rounds = 4 * Math.log2(blockLen) - 14;
        this.offs = [0, 1, 2, 3, 4, 5, 6, blockLen === 64 ? 7 : 11];

        const w = this.stSize * 2;
        this.s = new Uint32Array(w);
        this.m = new Uint32Array(w);
        this.ap = new Uint32Array(w);
        this.aq = new Uint32Array(w);
        this.tmp = new Uint32Array(w);
        this.s[0] = blockLen;
    }

    // Unused
    protected get(): number[] { return []; }
    protected set(..._args: number[]) { }

    protected process(buf: DataView, offset: number = 0) {
        for (let i = 0; i < this.m.length; i++)
            this.m[i] = buf.getUint32(offset + (i << 2), true);

        for (let i = 0; i < this.s.length; i++) {
            this.ap[i] = this.s[i] ^ this.m[i];
            this.aq[i] = this.m[i];
        }

        for (let r = 0; r < this.rounds; r += 2) {
            this.P(this.ap, this.tmp, r);
            this.Q(this.aq, this.tmp, r);
        }

        for (let i = 0; i < this.s.length; i++) this.s[i] ^= this.ap[i] ^ this.aq[i];
    }

    protected roundClean() {
        clean(this.m, this.ap, this.aq, this.tmp);
    }

    destroy() {
        this.destroyed = true;
        clean(this.s, this.buffer);
        this.roundClean();
    }

    override digestInto(out: TArg<Uint8Array>) {
        aexists(this);
        aoutput(out, this);
        this.finished = true;

        const threshold = this.blockLen - 12;
        let pos = this.pos;
        this.buffer[pos++] = 0x80;
        if (pos > threshold) {
            this.buffer.fill(0, pos);
            this.process(this.view);
            pos = 0;
        }
        this.buffer.fill(0, pos);
        const length = this.length * 8;
        this.view.setUint32(threshold, length >>> 0, true);
        this.view.setUint32(threshold + 4, (length / 2 ** 32) | 0, true);
        this.process(this.view);
        this.outputTransform();
        this.roundClean();

        const oview = out === this.buffer ? this.view : createView(out);
        for (let i = this.outputLen >>> 2, j = 0; i < this.s.length; i++, j += 4)
            oview.setUint32(j, this.s[i], true);
    }

    private G(x: Uint32Array, y: Uint32Array) {
        for (let i = 0; i < this.stSize; i++)
            column(x, i, this.stSize, this.offs, y, i << 1);
    }

    private P(x: Uint32Array, y: Uint32Array, round: number) {
        for (let i = 0; i < this.stSize; i++) x[i << 1] ^= (i << 4) ^ round;

        const r1 = round + 1;
        for (let i = 0; i < this.stSize; i++) {
            const j = i << 1;
            column(x, i, this.stSize, this.offs, y, j);
            y[j] ^= (i << 4) ^ r1;
        }
        this.G(y, x);
    }

    private Q(x: Uint32Array, y: Uint32Array, round: number) {
        for (let i = 0; i < this.stSize; i++) {
            const j = i << 1,
                tb = (((this.stSize - 1 - i) << 4) ^ round) & 0xFF,
                ch = (R_HI ^ (tb << 24)) >>> 0,
                lo = x[j] + R_LO;
            x[j + 1] += ch + (lo > _U32 ? 1 : 0);
            x[j] = lo;
        }

        const r1 = round + 1;
        for (let i = 0; i < this.stSize; i++) {
            const j = i << 1;
            column(x, i, this.stSize, this.offs, y, j);
            const tb = (((this.stSize - 1 - i) << 4) ^ r1) & 0xFF;
            const ch = (R_HI ^ (tb << 24)) >>> 0;
            const lo = y[j] + R_LO;
            y[j + 1] += ch + (lo > _U32 ? 1 : 0);
            y[j] = lo;
        }
        this.G(y, x);
    }

    private outputTransform() {
        this.ap.set(this.s);
        for (let r = 0; r < this.rounds; r += 2) this.P(this.ap, this.tmp, r);
        for (let i = 0; i < this.s.length; i++) this.s[i] ^= this.ap[i];
    }

    _cloneInto(to?: T): T {
        to ||= new (this.constructor as any)() as T;
        to.s.set(this.s);
        return this._cloneIntoMeta(to);
    }
}

abstract class KupynaDerived<T extends Kupyna<T>> implements Hash<KupynaDerived<T>> {
    readonly outputLen: number;
    readonly blockLen: number;
    readonly canXOF = false;
    protected h: Hash<T>;

    constructor(hash: CHash, private readonly slice: number) {
        ahash(hash);
        this.outputLen = Math.abs(slice);
        this.blockLen = hash.blockLen;
        this.h = hash.create();
    }

    destroy() { this.h.destroy(); }

    _cloneInto(to?: KupynaDerived<T>): KupynaDerived<T> {
        to ||= new (this.constructor as any)() as KupynaDerived<T>;
        to.h = this.h.clone();
        return to;
    }
    clone(): KupynaDerived<T> { return this._cloneInto(); }

    update(data: TArg<Uint8Array>): this {
        abytes(data, undefined, "data");
        this.h.update(data);
        return this;
    }

    digest(): TRet<Uint8Array> {
        const buffer = new Uint8Array(this.outputLen);
        this.digestInto(buffer);

        return buffer;
    }
    digestInto(buffer: TArg<Uint8Array>) {
        aoutput(buffer, this);
        buffer.set(this.h.digest().subarray(this.slice));
    }
}

/** Internal Kupyna-256 hash class */
export class _Kupyna256 extends Kupyna<_Kupyna256> {
    constructor() { super(64); }
}

/** Internal Kupyna-512 hash class */
export class _Kupyna512 extends Kupyna<_Kupyna512> {
    constructor() { super(128); }
}

/**
 * Kupyna-256 hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { kupyna256 } from "@li0ard/dstu/kupyna.js";
 * 
 * kupyna256(new Uint8Array([97, 98, 99]));
 * kupyna256.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const kupyna256: TRet<CHash<_Kupyna256>> = /* @__PURE__ */ createHasher(() => new _Kupyna256());

/**
 * Kupyna-512 hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { kupyna512 } from "@li0ard/dstu/kupyna.js";
 * 
 * kupyna512(new Uint8Array([97, 98, 99]));
 * kupyna512.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const kupyna512: TRet<CHash<_Kupyna512>> = /* @__PURE__ */ createHasher(() => new _Kupyna512());

/** Internal Kupyna-48 hash class */
export class _Kupyna48 extends KupynaDerived<_Kupyna256> {
    constructor() { super(kupyna256, -6); }
}

/** Internal Kupyna-304 hash class */
export class _Kupyna304 extends KupynaDerived<_Kupyna512> {
    constructor() { super(kupyna512, -38); }

}

/** Internal Kupyna-384 hash class */
export class _Kupyna384 extends KupynaDerived<_Kupyna512> {
    constructor() { super(kupyna512, -48); }
}

/**
 * Kupyna-48 hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { kupyna48 } from "@li0ard/dstu/kupyna.js";
 * 
 * kupyna48(new Uint8Array([97, 98, 99]));
 * kupyna48.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const kupyna48: TRet<CHash<_Kupyna48>> = /* @__PURE__ */ createHasher(() => new _Kupyna48());

/**
 * Kupyna-304 hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { kupyna304 } from "@li0ard/dstu/kupyna.js";
 * 
 * kupyna304(new Uint8Array([97, 98, 99]));
 * kupyna304.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const kupyna304: TRet<CHash<_Kupyna304>> = /* @__PURE__ */ createHasher(() => new _Kupyna304());

/**
 * Kupyna-384 hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { kupyna384 } from "@li0ard/dstu/kupyna.js";
 * 
 * kupyna384(new Uint8Array([97, 98, 99]));
 * kupyna384.create().update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const kupyna384: TRet<CHash<_Kupyna384>> = /* @__PURE__ */ createHasher(() => new _Kupyna384());