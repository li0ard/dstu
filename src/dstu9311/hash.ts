import { concatBytes, copyBytes, createHasher, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Dstu9311, DKE_1 } from "../dstu9311/index.js";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";
import { xorBytes } from "../utils.js";

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

/** GOST R 34.311-95 hash function */
export class Gost3431195 implements Hash<Gost3431195> {
    public readonly blockLen = 32;
    public readonly outputLen = 32;
    public readonly canXOF = false;
    private buffer: TArg<Uint8Array>;

    /** GOST R 34.311-95 hash function */
    constructor(private sbox: TArg<Uint8Array> = DKE_1) { this.buffer = new Uint8Array(); }

    /** Create hash instance */
    public static create(): Gost3431195 { return new Gost3431195(); }

    destroy() { this.buffer = new Uint8Array(); }

    clone(): Gost3431195 { return this._cloneInto(); }
    _cloneInto(to?: Gost3431195): Gost3431195 {
        to ||= new Gost3431195();
        to.buffer = new Uint8Array(this.buffer);
        to.sbox = this.sbox;

        return to;
    }

    update(data: TArg<Uint8Array>): this {
        this.buffer = concatBytes(this.buffer, data);
        return this;
    }

    digestInto(buf: TArg<Uint8Array>) {
        if(buf.length != this.outputLen) throw new Error("digestInto: Invalid buffer length");
        let len = 0n, checksum = 0n;
        const h = new Uint8Array(this.blockLen), m = copyBytes(this.buffer);
        for(let i = 0; i < m.length; i += this.blockLen) {
            let part = m.slice(i, i + this.blockLen).reverse();
            len += BigInt(part.length) * 8n;

            checksum = (checksum + bytesToNumberBE(part)) & r;
            if(part.length < this.blockLen)
                part = numberToBytesBE(bytesToNumberBE(part), this.blockLen);
            h.set(_step(h, part, this.sbox));
        }

        h.set(_step(
            _step(h, numberToBytesBE(len, this.blockLen), this.sbox),
            numberToBytesBE(checksum, this.blockLen),
            this.sbox
        ));
        buf.set(h.reverse());
        this.destroy();
    }

    digest(): TRet<Uint8Array> { 
        const buffer = new Uint8Array(this.outputLen);
        this.digestInto(buffer);

        return buffer;
    }
}

/** GOST R 34.311-95 hash function */
export const gost3431195 = createHasher(Gost3431195.create);