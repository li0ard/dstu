import { abytes, ahash, anumber, aoutput, createHasher, type CHash, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { bytesToUint64sLE, uint64sToBytesLE } from "../utils.js";
import { column } from "../kalyna/index.js";
import { numberToBytesLE } from "@noble/curves/utils.js";

const r = 0x00F0F0F0F0F0F0F3n;

abstract class Kupyna<T extends Kupyna<T>> implements Hash<Kupyna<T>> {
    readonly outputLen: number;
    readonly canXOF = false;

    private readonly rounds: number;
    private readonly stSize: number;
    private readonly threshold: number;
    protected s!: BigUint64Array;
    protected x!: Uint8Array;
    protected nx!: number;
    protected len!: bigint;

    constructor(public readonly blockLen: number) {
        anumber(blockLen, "blockLen");
        this.stSize = (blockLen / 2) / 4;
        this.threshold = blockLen - 12;
        this.rounds = 4 * Math.log2(blockLen) - 14;
        this.outputLen = blockLen / 2;

        this.s = new BigUint64Array(this.stSize);
        this.x = new Uint8Array(this.blockLen);
        this.nx = 0;
        this.len = 0n;

        this.s[0] = BigInt(this.blockLen);
    }

    destroy() {
        this.s[0] = BigInt(this.blockLen);
        this.s.fill(0n, 1);
        this.x.fill(0);
        this.nx = 0;
        this.len = 0n;
    }

    update(data: TArg<Uint8Array>): this {
        abytes(data, undefined, "data");
        this.len += BigInt(data.length);
    
        if (this.nx > 0) {
            const n = Math.min(this.blockLen - this.nx, data.length);
            this.x.set(data.subarray(0, n), this.nx);
            this.nx += n;
        
            if (this.nx === this.blockLen) {
                this.F(bytesToUint64sLE(this.x));
                this.nx = 0;
            }
        
            data = data.slice(n);
        }
    
        while (data.length >= this.blockLen) {
            this.F(bytesToUint64sLE(data.subarray(0, this.blockLen)));
            this.nx = 0;
            data = data.slice(this.blockLen);
        }
    
        if (data.length > 0) {
            this.x.set(data, 0);
            this.nx = data.length;
        }
    
        return this;
    }

    digest(): TRet<Uint8Array> {
        const buffer = new Uint8Array(this.outputLen);
        this.digestInto(buffer);
        return buffer;
    }

    digestInto(buffer: TArg<Uint8Array>) {
        aoutput(buffer, this);
        this.x[this.nx] = 0x80;
        this.nx++;

        const fillBytes = (start: number) => {
            const available = this.x.length - start;
            if (available > 0) this.x.fill(0, start, start + available);
        };

        if (this.nx > this.threshold) {
            fillBytes(this.nx);
            this.F(bytesToUint64sLE(this.x));
            this.nx = 0;
        }

        fillBytes(this.nx);
        this.x.set(numberToBytesLE(this.len * 8n, 12), this.threshold);
        this.F(bytesToUint64sLE(this.x));
        this.outputTransform();

        buffer.set(uint64sToBytesLE(this.s).subarray(this.outputLen));
        this.destroy();
    }

    private column(x: TArg<BigUint64Array>, i: number): bigint {
        return column(x, i, this.stSize, 1, 2, 3, 4, 5, 6, this.blockLen == 64 ? 7 : 11);
    }

    private G(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>) {
        for (let i = 0; i < this.stSize; i++) y[i] = this.column(x, i);
    }

    private P(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, round: bigint) {
        for(let i = 0n; i < BigInt(this.stSize); i++)
            x[Number(i)] ^= (i << 4n) ^ round;

        const r1 = round + 1n;
        for (let i = 0; i < this.stSize; i++)
            y[i] = this.column(x, i) ^ BigInt(i << 4) ^ r1;
        this.G(y, x);
    }

    private Q(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, round: bigint) {
        for(let j = 0n; j < BigInt(this.stSize); j++)
            x[Number(j)] += r ^ ((((BigInt(this.stSize - 1) - j) * 0x10n) ^ round) << 56n);

        const r1 = round + 1n;
        for (let i = 0; i < this.stSize; i++)
            y[i] = this.column(x, i) + (r ^ ((BigInt((this.stSize - 1 - i) * 16) ^ r1) << 56n));
        this.G(y, x);
    }

    private outputTransform() {
        const t1 = new BigUint64Array(this.s), t2 = new BigUint64Array(this.stSize);
        
        for(let r = 0n; r < BigInt(this.rounds); r += 2n) this.P(t1, t2, r);
        for(let column = 0; column < this.stSize; column++) this.s[column] ^= t1[column];
    }

    private F(b: TArg<BigUint64Array>) {
        const AQ1 = new BigUint64Array(this.stSize);
        const AP1 = new BigUint64Array(this.stSize);
        const tmp = new BigUint64Array(this.stSize);

        for(let column = 0; column < this.stSize; column++) {
            AP1[column] = this.s[column] ^ b[column];
            AQ1[column] = b[column];
        }

        for(let r = 0n; r < BigInt(this.rounds); r += 2n) {
            this.P(AP1, tmp, r);
            this.Q(AQ1, tmp, r);
        }

        for(let column = 0; column < this.stSize; column++)
            this.s[column] ^= AP1[column] ^ AQ1[column];
    }

    clone(): Kupyna<T> { return this._cloneInto(); }
    abstract _cloneInto(to?: Kupyna<T>): Kupyna<T>;
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

    abstract _cloneInto(to?: KupynaDerived<T>): KupynaDerived<T>;
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
    _cloneInto(to?: _Kupyna256): _Kupyna256 {
        to ||= new _Kupyna256();
        to.s.set(this.s);
        to.x.set(this.x);
        to.nx = this.nx;
        to.len = this.len;

        return to;
    }
    /** Create hash instance */
    static create(): _Kupyna256 { return new _Kupyna256(); }
}

/** Internal Kupyna-512 hash class */
export class _Kupyna512 extends Kupyna<_Kupyna512> {
    constructor() { super(128); }
    _cloneInto(to?: _Kupyna512): _Kupyna512 {
        to ||= new _Kupyna512();
        to.s.set(this.s);
        to.x.set(this.x);
        to.nx = this.nx;
        to.len = this.len;

        return to;
    }
    /** Create hash instance */
    static create(): _Kupyna512 { return new _Kupyna512(); }
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
export const kupyna256 = createHasher(_Kupyna256.create);
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
export const kupyna512 = createHasher(_Kupyna512.create);

/** Internal Kupyna-48 hash class */
export class _Kupyna48 extends KupynaDerived<_Kupyna256> {
    constructor() { super(kupyna256, -6); }
    _cloneInto(to?: _Kupyna48): _Kupyna48 {
        to ||= new _Kupyna48();
        to.h = this.h.clone();
        return to;
    }
    /** Create hash instance */
    static create(): _Kupyna48 { return new _Kupyna48(); }
}

/** Internal Kupyna-304 hash class */
export class _Kupyna304 extends KupynaDerived<_Kupyna512> {
    constructor() { super(kupyna512, -38); }
    _cloneInto(to?: _Kupyna304): _Kupyna304 {
        to ||= new _Kupyna304();
        to.h = this.h.clone();
        return to;
    }
    /** Create hash instance */
    static create(): _Kupyna304 { return new _Kupyna304(); }
}

/** Internal Kupyna-384 hash class */
export class _Kupyna384 extends KupynaDerived<_Kupyna512> {
    constructor() { super(kupyna512, -48); }
    _cloneInto(to?: _Kupyna384): _Kupyna384 {
        to ||= new _Kupyna384();
        to.h = this.h.clone();
        return to;
    }
    /** Create hash instance */
    static create(): _Kupyna384 { return new _Kupyna384(); }
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
export const kupyna48 = createHasher(_Kupyna48.create);
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
export const kupyna304 = createHasher(_Kupyna304.create);
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
export const kupyna384 = createHasher(_Kupyna384.create);

export * from "./kmac.js";