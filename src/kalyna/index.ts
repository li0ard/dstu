import { abool, abytes, anumber, type TArg, type TRet } from "@noble/hashes/utils.js";
import { T, S, MDS_MATRIX_inv, genTable } from "../const.js";
import type { Cipher } from "../types.js";
import { _U32, u32ToBytesLE, bytesToU32LE } from "../utils.js";

const swap_block = (k: Uint32Array, words: number) => {
    if (words <= 1) return;
    const l = k[0], h = k[1];
    k.copyWithin(0, 2, words * 2);
    k[words * 2 - 2] = l;
    k[words * 2 - 1] = h;
}

export const column = (
    x: Uint32Array, i: number, N: number,
    offs: ArrayLike<number>,
    out: Uint32Array, o: number,
    table: Uint32Array[] = T,
    sign: 1 | -1 = -1
) => {
    const m = N - 1;
    const j0 = ((i + sign * offs[0]) & m) << 1,
        j1 = ((i + sign * offs[1]) & m) << 1,
        j2 = ((i + sign * offs[2]) & m) << 1,
        j3 = ((i + sign * offs[3]) & m) << 1,
        j4 = (((i + sign * offs[4]) & m) << 1) | 1,
        j5 = (((i + sign * offs[5]) & m) << 1) | 1,
        j6 = (((i + sign * offs[6]) & m) << 1) | 1,
        j7 = (((i + sign * offs[7]) & m) << 1) | 1;

    const b0 = (x[j0] & 0xFF) << 1,
        b1 = ((x[j1] >>> 8) & 0xFF) << 1,
        b2 = ((x[j2] >>> 16) & 0xFF) << 1,
        b3 = (x[j3] >>> 24) << 1,
        b4 = (x[j4] & 0xFF) << 1,
        b5 = ((x[j5] >>> 8) & 0xFF) << 1,
        b6 = ((x[j6] >>> 16) & 0xFF) << 1,
        b7 = (x[j7] >>> 24) << 1;

    const t0 = table[0], t1 = table[1], t2 = table[2], t3 = table[3],
        t4 = table[4], t5 = table[5], t6 = table[6], t7 = table[7];

    out[o] = t0[b0] ^ t1[b1] ^ t2[b2] ^ t3[b3] ^ t4[b4] ^ t5[b5] ^ t6[b6] ^ t7[b7];
    out[o + 1] = t0[b0 | 1] ^ t1[b1 | 1] ^ t2[b2 | 1] ^ t3[b3 | 1] ^
        t4[b4 | 1] ^ t5[b5 | 1] ^ t6[b6 | 1] ^ t7[b7 | 1];
};

const IS = /* @__PURE__ */ S.map(i => i.map((_, j) => i.indexOf(j))),
    IT = /* @__PURE__ */ genTable(MDS_MATRIX_inv, IS);

export abstract class Kalyna implements Cipher {
    /** Block size */
    readonly blockSize: number;
    /** Key size */
    readonly keySize: number;

    private erk!: Uint32Array;
    private drk!: Uint32Array;
    private readonly numRounds: number;
    private readonly glOffset: number;
    private wordOffsets: number[];

    /** Kalyna abstract class */
    constructor(key: TArg<Uint8Array>, public readonly N: number, isDouble: boolean = false) {
        anumber(N, "N");
        abool(isDouble, "isDouble");
        if(N < 2 || (N & (N - 1)) !== 0) throw new Error("N must be power of 2 and >= 2");
        this.blockSize = N << 3;
        this.keySize = this.blockSize;
        if(isDouble) this.keySize *= 2;
        abytes(key, this.keySize, "key");

        this.wordOffsets = Array.from({length: 8}, (_, j) => Math.floor(j * this.N / 8));
        const X = 6 + 4 * Math.log2(N) + (isDouble ? 4 : 0);
        this.numRounds = X - (N > 2 || isDouble ? 1 : 0);
        this.glOffset = X * N;
        this.expandKey(key);
    }

    private expandKey(key: Uint8Array) {
        const N2 = this.N * 2,
            log2N = Math.log2(this.N),
            isDoubleKey = (this.keySize === this.blockSize * 2),
            R = isDoubleKey ? (6 + 2 * log2N) : (4 + 2 * log2N),
            rk = new Uint32Array(R * this.N * 4),
            ks = new Uint32Array(N2), ksc = new Uint32Array(N2),
            t1 = new Uint32Array(N2), t2 = new Uint32Array(N2);
        t1[0] = isDoubleKey ? (N2 + 2 * log2N + 1) : (N2 + 1);

        const keys = bytesToU32LE(key),
            _0 = new Uint32Array(N2);
        const k = new Uint32Array(isDoubleKey ? N2 * 2 : N2);
        if (isDoubleKey) {
            const ka = keys.subarray(0, N2);
            this.addkey(t1, t2, ka);
            this.G(t2, t1, keys.subarray(N2));
            this.GL(t1, t2, ka);
            this.G(t2, ks, _0);
            k.set(keys);
        } else {
            k.set(keys.subarray(0, N2));
            this.addkey(t1, t2, keys);
            this.G(t2, t1, keys);
            this.GL(t1, t2, keys);
            this.G(t2, ks, _0);
        }

        let cl = 0x00010001, ch = 0x00010001;
        for (let i = 0; i < R; i++) {
            const offset = i * N2;
            if (i > 0) {
                if (!isDoubleKey) swap_block(k, this.N);
                else if (i % 2 === 0) swap_block(k, N2);
            }

            const keySource = isDoubleKey
                ? (i % 2 === 0 ? k.subarray(0, N2) : k.subarray(N2))
                : k;
            for (let j = 0; j < N2; j += 2) {
                const lo = ks[j] + cl;
                ksc[j] = lo;
                ksc[j + 1] = ks[j + 1] + ch + (lo > _U32 ? 1 : 0);
            }
            this.addkey(keySource, t2, ksc);
            this.G(t2, t1, ksc);
            this.GL(t1, rk.subarray(offset * 2), ksc);

            if (i < R - 1)
                this.makeOddKey(rk.subarray(offset * 2), rk.subarray((offset + this.N) * 2));

            ch = ((ch << 1) | (cl >>> 31)) >>> 0;
            cl = (cl << 1) >>> 0;
        }

        this.erk = rk.slice();
        for (let i = ((R * 2 - 3) * this.N); i > 0; i -= this.N)
            this.IMC(rk.subarray(i * 2));
        this.drk = rk;
    }

    private makeOddKey(evenkey: Uint32Array, oddkey: Uint32Array) {
        const offset = 2 * this.N + 3,
            ev = u32ToBytesLE(evenkey.subarray(0, this.N * 2)),
            od = new Uint8Array(this.blockSize);
        od.set(ev.subarray(offset, this.blockSize));
        od.set(ev.subarray(0, offset), this.blockSize - offset);
        oddkey.set(bytesToU32LE(od));
    }

    private addkey(x: Uint32Array, y: Uint32Array, k: Uint32Array, ko = 0) {
        for (let j = 0, e = this.N * 2; j < e; j += 2) {
            const lo = x[j] + k[ko + j];
            y[j + 1] = x[j + 1] + k[ko + j + 1] + (lo > _U32 ? 1 : 0);
            y[j] = lo;
        }
    }

    private subkey(x: Uint32Array, y: Uint32Array, k: Uint32Array, ko = 0) {
        for (let j = 0, e = this.N * 2; j < e; j += 2) {
            const lo = x[j] - k[ko + j];
            y[j + 1] = x[j + 1] - k[ko + j + 1] - (lo < 0 ? 1 : 0);
            y[j] = lo;
        }
    }

    private G(x: Uint32Array, y: Uint32Array, k: Uint32Array, ko = 0) {
        for (let i = 0; i < this.N; i++) {
            const j = i << 1;
            column(x, i, this.N, this.wordOffsets, y, j);
            y[j] ^= k[ko + j];
            y[j + 1] ^= k[ko + j + 1];
        }
    }

    private GL(x: Uint32Array, y: Uint32Array, k: Uint32Array, ko = 0) {
        for (let i = 0; i < this.N; i++) {
            const j = i << 1;
            column(x, i, this.N, this.wordOffsets, y, j);
            const lo = y[j] + k[ko + j];
            y[j + 1] += k[ko + j + 1] + (lo > _U32 ? 1 : 0);
            y[j] = lo;
        }
    }

    private IG(x: Uint32Array, y: Uint32Array, k: Uint32Array, ko = 0) {
        for (let i = 0; i < this.N; i++) {
            const j = i << 1;
            column(x, i, this.N, this.wordOffsets, y, j, IT, 1);
            y[j] ^= k[ko + j];
            y[j + 1] ^= k[ko + j + 1];
        }
    }

    private IMC(x: Uint32Array) {
        const [s0, s1, s2, s3] = S;
        const [i0, i1, i2, i3, i4, i5, i6, i7] = IT;
        for (let j = 0, e = this.N * 2; j < e; j += 2) {
            const l = x[j], h = x[j + 1];
            const a0 = s0[l & 0xFF] << 1,
                a1 = s1[(l >>> 8) & 0xFF] << 1,
                a2 = s2[(l >>> 16) & 0xFF] << 1,
                a3 = s3[l >>> 24] << 1,
                a4 = s0[h & 0xFF] << 1,
                a5 = s1[(h >>> 8) & 0xFF] << 1,
                a6 = s2[(h >>> 16) & 0xFF] << 1,
                a7 = s3[h >>> 24] << 1;
            x[j] = i0[a0] ^ i1[a1] ^ i2[a2] ^ i3[a3] ^ i4[a4] ^ i5[a5] ^ i6[a6] ^ i7[a7];
            x[j + 1] = i0[a0 | 1] ^ i1[a1 | 1] ^ i2[a2 | 1] ^ i3[a3 | 1] ^
                i4[a4 | 1] ^ i5[a5 | 1] ^ i6[a6 | 1] ^ i7[a7 | 1];
        }
    }

    private IGL(x: Uint32Array, y: Uint32Array) {
        const m = this.N - 1;
        const [is0, is1, is2, is3] = IS;
        for (let i = 0; i < this.N; i++) {
            const j0 = ((i + this.wordOffsets[0]) & m) << 1,
                j1 = ((i + this.wordOffsets[1]) & m) << 1,
                j2 = ((i + this.wordOffsets[2]) & m) << 1,
                j3 = ((i + this.wordOffsets[3]) & m) << 1,
                j4 = (((i + this.wordOffsets[4]) & m) << 1) | 1,
                j5 = (((i + this.wordOffsets[5]) & m) << 1) | 1,
                j6 = (((i + this.wordOffsets[6]) & m) << 1) | 1,
                j7 = (((i + this.wordOffsets[7]) & m) << 1) | 1;

            const lo = is0[x[j0] & 0xFF] |
                (is1[(x[j1] >>> 8) & 0xFF] << 8) |
                (is2[(x[j2] >>> 16) & 0xFF] << 16) |
                (is3[x[j3] >>> 24] << 24);
            const hi = is0[x[j4] & 0xFF] |
                (is1[(x[j5] >>> 8) & 0xFF] << 8) |
                (is2[(x[j6] >>> 16) & 0xFF] << 16) |
                (is3[x[j7] >>> 24] << 24);

            const d = i << 1, l = (lo >>> 0) - this.drk[d];
            y[d + 1] = (hi >>> 0) - this.drk[d + 1] - (l < 0 ? 1 : 0);
            y[d] = l;
        }
    }

    /** Encrypt block */
    encrypt(block: TArg<Uint8Array>): TRet<Uint8Array> {
        abytes(block, this.blockSize, "block");
        const t1 = new Uint32Array(this.N * 2), t2 = new Uint32Array(this.N * 2);
        this.addkey(bytesToU32LE(block), t1, this.erk);

        for (let i = 0; i < this.numRounds; i++) {
            const ko = (this.N + i * this.N) * 2;
            if (i % 2 === 0) this.G(t1, t2, this.erk, ko);
            else this.G(t2, t1, this.erk, ko);
        }

        this.GL(t2, t1, this.erk, this.glOffset * 2);
        return u32ToBytesLE(t1) as TRet<Uint8Array>;
    }

    /** Decrypt block */
    decrypt(block: TArg<Uint8Array>): TRet<Uint8Array> {
        abytes(block, this.blockSize, "block");
        const t1 = new Uint32Array(this.N * 2), t2 = new Uint32Array(this.N * 2);
        this.subkey(bytesToU32LE(block), t1, this.drk, this.glOffset * 2);
        this.IMC(t1);

        for (let i = 0; i < this.numRounds; i++) {
            const ko = (this.glOffset - this.N - i * this.N) * 2;
            if (i % 2 === 0) this.IG(t1, t2, this.drk, ko);
            else this.IG(t2, t1, this.drk, ko);
        }

        this.IGL(t2, t1);
        return u32ToBytesLE(t1) as TRet<Uint8Array>;
    }
}

/** Kalyna 128/128 bit version */
export class Kalyna128 extends Kalyna {
    constructor(key: TArg<Uint8Array>) { super(key, 2); }
}
/** Kalyna 128/256 bit version */
export class Kalyna128_256 extends Kalyna {
    constructor(key: TArg<Uint8Array>) { super(key, 2, true); }
}

/** Kalyna 256 bit version */
export class Kalyna256 extends Kalyna {
    constructor(key: TArg<Uint8Array>) { super(key, 4); }
}
/** Kalyna 256/512 bit version */
export class Kalyna256_512 extends Kalyna {
    constructor(key: TArg<Uint8Array>) { super(key, 4, true); }
}

/** Kalyna 512 bit version */
export class Kalyna512 extends Kalyna {
    constructor(key: TArg<Uint8Array>) { super(key, 8); }
}