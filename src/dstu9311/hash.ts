import { abytes, aexists, aoutput, clean, createHasher, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Dstu9311, DKE_1 } from "../dstu9311/index.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { _HMAC } from "@noble/hashes/hmac.js";
import { HashMD } from "@noble/hashes/_md.js";

const C3 = new Uint8Array([
    0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff,
    0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
    0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00
]);

const U = new Uint8Array(32),
    V = new Uint8Array(32),
    W = new Uint8Array(32),
    X = new Uint8Array(32),
    KEY = new Uint8Array(32),
    BLOCK = new Uint8Array(32),
    TMP = new Uint8Array(8),
    CT = new Uint8Array(8);

const A = (x: TArg<Uint8Array>) => {
    for (let i = 0; i < 8; i++) TMP[i] = x[24 + i] ^ x[16 + i];
    x.copyWithin(8, 0, 24);
    x.set(TMP);
}

const chi = (y: TArg<Uint8Array>) => {
    const a = y[30] ^ y[28] ^ y[26] ^ y[24] ^ y[6] ^ y[0],
        b = y[31] ^ y[29] ^ y[27] ^ y[25] ^ y[7] ^ y[1];
    y.copyWithin(2, 0, 30);
    y[0] = a;
    y[1] = b;
}

const deriveKey = (u: TArg<Uint8Array>, v: TArg<Uint8Array>) => {
    for (let n = 0; n < 32; n++) {
        const i = 31 - (n >> 2) - ((n & 3) << 3);
        KEY[n] = u[i] ^ v[i];
    }
}

const encrypt = (cipher: Dstu9311, plaintext: TArg<Uint8Array>, offset: number) => {
    for (let i = 0; i < 8; i++) CT[i] = plaintext[offset + 7 - i];
    const e = cipher.encrypt(CT);
    for (let i = 0; i < 8; i++) X[offset + i] = e[7 - i];
}

const _step = (
    hin: TArg<Uint8Array>,
    m: TArg<Uint8Array>,
    sbox: TArg<Uint8Array>,
    out: TArg<Uint8Array>
) => {
    deriveKey(hin, m);
    const k1 = new Dstu9311(KEY, sbox);

    U.set(hin);
    A(U);
    V.set(m);
    A(V);
    A(V);
    deriveKey(U, V);
    const k2 = new Dstu9311(KEY, sbox);

    A(U);
    for (let i = 0; i < 32; i++) U[i] ^= C3[i];
    A(V);
    A(V);
    deriveKey(U, V);
    const k3 = new Dstu9311(KEY, sbox);

    A(U);
    A(V);
    A(V);
    deriveKey(U, V);
    const k4 = new Dstu9311(KEY, sbox);

    encrypt(k4, hin, 0);
    encrypt(k3, hin, 8);
    encrypt(k2, hin, 16);
    encrypt(k1, hin, 24);

    for (let i = 0; i < 12; i++) chi(X);
    for (let i = 0; i < 32; i++) W[i] = X[i] ^ m[i];
    chi(W);
    for (let i = 0; i < 32; i++) X[i] = hin[i] ^ W[i];
    for (let i = 0; i < 61; i++) chi(X);

    out.set(X);
}

/** Internal GOST 34.311-95 hash class */
export class _Gost3431195 extends HashMD<_Gost3431195> {
    private h = new Uint8Array(32);
    private checksum = new Uint8Array(32);

    /** Internal GOST 34.311-95 hash class */
    constructor(private sbox: TArg<Uint8Array> = DKE_1) {
        super(32, 32, 0, true);
        abytes(sbox, 64, "sbox");
    }

    protected process(view: DataView, offset: number = 0) {
        let c = 0;
        for (let i = 0; i < 32; i++) {
            const b = view.getUint8(offset + i),
                s = this.checksum[i] + b + c;
            this.checksum[i] = s;
            c = s >> 8;
            BLOCK[31 - i] = b;
        }
        _step(this.h, BLOCK, this.sbox, this.h);
    }

    // Unused
    protected get(): number[] { return []; }
    protected set(...args: number[]) {}

    protected roundClean() {
        clean(U, V, W, X, KEY, BLOCK, TMP, CT);
    }

    override digestInto(out: TArg<Uint8Array>) {
        aexists(this);
        aoutput(out, this);
        this.finished = true;
        if (this.pos > 0) {
            this.buffer.fill(0, this.pos);
            this.process(this.view);
        }

        _step(this.h, numberToBytesBE(BigInt(this.length) * 8n, 32), this.sbox, this.h);
        for (let i = 0; i < 32; i++) BLOCK[i] = this.checksum[31 - i];
        _step(this.h, BLOCK, this.sbox, this.h);
        for (let i = 0; i < 32; i++) out[i] = this.h[31 - i];
        this.roundClean();
    }

    destroy() {
        this.destroyed = true;
        clean(this.buffer, this.h, this.checksum);
    }

    _cloneInto(to?: _Gost3431195): _Gost3431195 {
        to ||= new _Gost3431195(this.sbox);
        this._cloneIntoMeta(to);
        to.sbox = this.sbox;
        to.h.set(this.h);
        to.checksum.set(this.checksum);

        return to;
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
export const gost3431195 = createHasher(() => new _Gost3431195());

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