import { concatBytes, createHasher, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { bytesToUint64sLE, numberToBytesLE, uint64sToBytesLE } from "../utils.js";
import { column } from "../kalyna/index.js";

const r = 0x00F0F0F0F0F0F0F3n;

abstract class Kupyna<T extends Kupyna<T>> implements Hash<Kupyna<T>> {
    public readonly outputLen: number;
    public readonly canXOF = false;

    private readonly rounds: number;
    private readonly stSize: number;
    private readonly threshold: number;
    protected s!: BigUint64Array;
    protected x!: Uint8Array;
    protected nx!: number;
    protected len!: bigint;

    constructor(public readonly blockLen: number) {
        this.stSize = (blockLen / 2) / 4;
        this.threshold = blockLen - 12;
        this.rounds = 4 * Math.log2(blockLen) - 14;
        this.outputLen = blockLen / 2;
        this.destroy();
    }

    destroy() {
        this.s = new BigUint64Array(this.stSize);
        this.x = new Uint8Array(this.blockLen);
        this.nx = 0;
        this.len = 0n;

        this.s[0] = BigInt(this.blockLen);
    }

    update(data: TArg<Uint8Array>): this {
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

    abstract clone(): Kupyna<T>;
    abstract _cloneInto(): Kupyna<T>;
}

abstract class KupynaDerived<T extends Kupyna<T>> implements Hash<KupynaDerived<T>> {
    readonly outputLen: number;
    readonly blockLen: number;
    readonly canXOF = false;
    buffer: Uint8Array = new Uint8Array();

    constructor(public hash: () => Kupyna<T>, private readonly slice: number) {
        this.outputLen = Math.abs(slice);
        this.blockLen = hash().blockLen;
    }

    destroy() {}

    abstract clone(): KupynaDerived<T>;
    abstract _cloneInto(): KupynaDerived<T>;

    update(data: TArg<Uint8Array>): this {
        this.buffer = concatBytes(this.buffer, data);
        return this;
    }

    digest(): TRet<Uint8Array> { 
        const buffer = new Uint8Array(this.outputLen);
        this.digestInto(buffer);

        return buffer;
    }
    digestInto(buffer: TArg<Uint8Array>) {
        buffer.set(this.hash().update(this.buffer).digest().subarray(this.slice))
    }
}

/** Kupyna 256 bit version */
export class Kupyna256 extends Kupyna<Kupyna256> {
    /** Kupyna 256 bit version */
    constructor() { super(64); }
    _cloneInto(to?: Kupyna256): Kupyna256 {
        to ||= new Kupyna256();
        to.s = new BigUint64Array(this.s);
        to.x = new Uint8Array(this.x);
        to.nx = this.nx;
        to.len = this.len;

        return to;
    }
    clone(): Kupyna256 { return this._cloneInto(); }
    /** Create hash instance */
    public static create(): Kupyna256 { return new Kupyna256(); }
}

/** Kupyna 512 bit version */
export class Kupyna512 extends Kupyna<Kupyna512> {
    /** Kupyna 512 bit version */
    constructor() { super(128); }
    _cloneInto(to?: Kupyna512): Kupyna512 {
        to ||= new Kupyna512();
        to.s = new BigUint64Array(this.s);
        to.x = new Uint8Array(this.x);
        to.nx = this.nx;
        to.len = this.len;

        return to;
    }
    clone(): Kupyna512 { return this._cloneInto(); }
    /** Create hash instance */
    public static create(): Kupyna512 { return new Kupyna512(); }
}

/** Kupyna 48 bit version */
export class Kupyna48 extends KupynaDerived<Kupyna256> {
    /** Kupyna 48 bit version */
    constructor() { super(Kupyna256.create, -6); }
    /** Create hash instance */
    public static create(): Kupyna48 { return new Kupyna48(); }
    _cloneInto(to?: Kupyna48): Kupyna48 {
        to ||= new Kupyna48();
        to.buffer = new Uint8Array(this.buffer);
        return to;
    }
    clone(): Kupyna48 { return this._cloneInto(); }
}

/** Kupyna 304 bit version */
export class Kupyna304 extends KupynaDerived<Kupyna512> {
    /** Kupyna 304 bit version */
    constructor() { super(Kupyna512.create, -38); }
    /** Create hash instance */
    public static create(): Kupyna304 { return new Kupyna304(); }
    _cloneInto(to?: Kupyna304): Kupyna304 {
        to ||= new Kupyna304();
        to.buffer = new Uint8Array(this.buffer);
        return to;
    }
    clone(): Kupyna304 { return this._cloneInto(); }
}

/** Kupyna 384 bit version */
export class Kupyna384 extends KupynaDerived<Kupyna512> {
    /** Kupyna 384 bit version */
    constructor() { super(Kupyna512.create, -48); }
    /** Create hash instance */
    public static create(): Kupyna384 { return new Kupyna384(); }
    _cloneInto(to?: Kupyna384): Kupyna384 {
        to ||= new Kupyna384();
        to.buffer = new Uint8Array(this.buffer);
        return to;
    }
    clone(): Kupyna384 { return this._cloneInto(); }
}

/** Kupyna 48 bit version */
export const kupyna48 = createHasher(Kupyna48.create);
/** Kupyna 256 bit version */
export const kupyna256 = createHasher(Kupyna256.create);
/** Kupyna 304 bit version */
export const kupyna304 = createHasher(Kupyna304.create);
/** Kupyna 384 bit version */
export const kupyna384 = createHasher(Kupyna384.create);
/** Kupyna 512 bit version */
export const kupyna512 = createHasher(Kupyna512.create);

export * from "./kmac.js";