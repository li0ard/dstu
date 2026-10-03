import { abytes, aoutput, clean, concatBytes, copyBytes, createHasher, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Dstu9311, DKE_1 } from "../dstu9311/index.js";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";
import { xorBytes } from "../utils.js";
import { _HMAC } from "@noble/hashes/hmac.js";

const r = (1n << 256n) - 1n;
const C3 = new Uint8Array([
    0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff,
    0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
    0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00
]);

const A = (x: TArg<Uint8Array>): TRet<Uint8Array> => concatBytes(
    xorBytes(x.subarray(24,32), x.subarray(16,24)),
    x.subarray(0,24)
);

const P = (x: TArg<Uint8Array>): TRet<Uint8Array> => new Uint8Array([
    x[31], x[23], x[15], x[7], x[30], x[22], x[14], x[6],
    x[29], x[21], x[13], x[5], x[28], x[20], x[12], x[4],
    x[27], x[19], x[11], x[3], x[26], x[18], x[10], x[2],
    x[25], x[17], x[9], x[1], x[24], x[16], x[8], x[0]
]);

const chi = (Y: TArg<Uint8Array>): TRet<Uint8Array> => new Uint8Array([
    Y[30] ^ Y[28] ^ Y[26] ^ Y[24] ^ Y[6] ^ Y[0],
    Y[31] ^ Y[29] ^ Y[27] ^ Y[25] ^ Y[7] ^ Y[1],
    ...Y.subarray(0,30)
]);

const _getCipher = (
    u: TArg<Uint8Array>,
    v: TArg<Uint8Array>,
    sbox: TArg<Uint8Array>
): Dstu9311 => new Dstu9311(P(xorBytes(u, v)), sbox);


const _step = (
    hin: TArg<Uint8Array>,
    m: TArg<Uint8Array>,
    sbox: TArg<Uint8Array>
): TRet<Uint8Array> => {
    const k1 = _getCipher(hin,m,sbox);

    let u = A(hin), v = A(A(m));
    const k2 = _getCipher(u,v,sbox);

    u = xorBytes(A(u), C3), v = A(A(v));
    const k3 = _getCipher(u,v,sbox);

    u = A(u), v = A(A(v));
    const k4 = _getCipher(u,v,sbox);

    const x = concatBytes(
        k4.encrypt(hin.slice(0,8).reverse()).reverse(),
        k3.encrypt(hin.slice(8,16).reverse()).reverse(),
        k2.encrypt(hin.slice(16,24).reverse()).reverse(),
        k1.encrypt(hin.slice(24,32).reverse()).reverse(),
    );
    for(let i = 0; i < 12; i++) x.set(chi(x));

    x.set(xorBytes(
        hin,
        chi(xorBytes(x, m))
    ));

    for(let i = 0; i < 61; i++) x.set(chi(x));

    return x;
}

/** Internal GOST 34.311-95 hash class */
export class _Gost3431195 implements Hash<_Gost3431195> {
    readonly blockLen = 32;
    readonly outputLen = 32;
    readonly canXOF = false;
    private buffer = new Uint8Array(32);
    private pos = 0;
    private h = new Uint8Array(32);
    private len = 0n;
    private checksum = 0n;

    /** Internal GOST 34.311-95 hash class */
    constructor(private sbox: TArg<Uint8Array> = DKE_1) {
        abytes(sbox, 64, "sbox");
    }

    /** Create hash instance */
    static create(): _Gost3431195 { return new _Gost3431195(); }

    destroy() {
        clean(this.buffer, this.h);
        this.pos = 0;
        this.len = 0n;
        this.checksum = 0n;
    }

    clone(): _Gost3431195 { return this._cloneInto(); }
    _cloneInto(to?: _Gost3431195): _Gost3431195 {
        to ||= new _Gost3431195();
        to.sbox = this.sbox;
        to.buffer.set(this.buffer);
        to.pos = this.pos;
        to.h.set(this.h);
        to.len = this.len;
        to.checksum = this.checksum;

        return to;
    }

    private processBlock(block: TArg<Uint8Array>) {
        const rev = copyBytes(block).reverse();
        this.len += 256n;
        this.checksum = (this.checksum + bytesToNumberBE(rev)) & r;
        this.h.set(_step(this.h, rev, this.sbox));
    }

    update(data: TArg<Uint8Array>): this {
        abytes(data);
        let offset = 0;
        if (this.pos > 0) {
            const take = Math.min(this.blockLen - this.pos, data.length);
            this.buffer.set(data.subarray(0, take), this.pos);
            this.pos += take;
            offset = take;
            if (this.pos === this.blockLen) {
                this.processBlock(this.buffer);
                this.pos = 0;
            }
        }

        for (; offset + this.blockLen <= data.length; offset += this.blockLen)
            this.processBlock(data.subarray(offset, offset + this.blockLen));

        if (offset < data.length) {
            this.buffer.set(data.subarray(offset), 0);
            this.pos = data.length - offset;
        }

        return this;
    }

    digestInto(buf: TArg<Uint8Array>) {
        aoutput(buf, this);
        if (this.pos > 0) {
            const part = new Uint8Array(this.blockLen);
            part.set(this.buffer.slice(0, this.pos).reverse(), this.blockLen - this.pos);
            this.len += BigInt(this.pos) * 8n;
            this.checksum = (this.checksum + bytesToNumberBE(part)) & r;
            this.h.set(_step(this.h, part, this.sbox));
        }

        const res = _step(
            _step(this.h, numberToBytesBE(this.len, this.blockLen), this.sbox),
            numberToBytesBE(this.checksum, this.blockLen),
            this.sbox
        );
        buf.set(res.reverse());
        this.destroy();
    }

    digest(): TRet<Uint8Array> { 
        const buffer = new Uint8Array(this.outputLen);
        this.digestInto(buffer);

        return buffer;
    }
}

/**
 * GOST 34.311-95 hash function
 * 
 * @param msg - message bytes to hash.
 * @returns Digest bytes.
 * @example
 * ```ts
 * import { gost3431195 } from "@li0ard/dstu/dstu9311.js";
 * 
 * gost3431195(new Uint8Array([97, 98, 99]));
 * gost3431195.create(sbox?).update(new Uint8Array([97, 98, 99])).digest();
 * ```
 */
export const gost3431195 = createHasher(_Gost3431195.create);

/**
 * HMAC over GOST 34.311-95 hash function
 * 
 * @param key - authentication key bytes
 */
export class Gost3431195HMAC extends _HMAC<_Gost3431195> {
    constructor(key: TArg<Uint8Array>) { super(gost3431195, key); }
}

/**
 * HMAC over GOST 34.311-95 hash function
 * 
 * @param key - authentication key bytes
 * @param message - message bytes to authenticate
 * @returns Authentication tag bytes.
 * @example
 * ```ts
 * import { gost3431195Hmac } from "@li0ard/dstu/dstu9311.js";
 * const key = new Uint8Array([1, 2, 3]);
 * const message = new Uint8Array([4, 5, 6]);
 * const mac = gost3431195Hmac(key, message);
 * ```
 */
export const gost3431195Hmac = (key: TArg<Uint8Array>, msg: TArg<Uint8Array>): TRet<Uint8Array> =>
    new Gost3431195HMAC(key).update(msg).digest();