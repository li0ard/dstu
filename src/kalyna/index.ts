import type { TArg, TRet } from "@noble/hashes/utils.js";
import { IS, IT, T, S } from "../const.js";
import { bytesToUint64sLE, uint64sToBytesLE, byte } from "../utils.js";
import type { Cipher } from "../types.js";

const swap_block = (k: TArg<BigUint64Array>, N: number) => {
    if (N <= 1) return;
    const t = k[0];
    for (let i = 0; i < N - 1; i++) k[i] = k[i + 1];
    k[N - 1] = t;
}

export const column = (
    x: TArg<BigUint64Array>, i: number, N: number,
    c1: number, c2: number, c3: number,
    c4: number, c5: number, c6: number, c7: number
): bigint => (
    T[0][byte(x[(i + N) % N])] ^ // c0 - always 0 for both Kalyna and Kupyna
    T[1][byte(x[(i - c1 + N) % N] >> 8n)] ^
    T[2][byte(x[(i - c2 + N) % N] >> 16n)] ^
    T[3][byte(x[(i - c3 + N) % N] >> 24n)] ^
    T[4][byte(x[(i - c4 + N) % N] >> 32n)] ^
    T[5][byte(x[(i - c5 + N) % N] >> 40n)] ^
    T[6][byte(x[(i - c6 + N) % N] >> 48n)] ^
    T[7][byte(x[(i - c7 + N) % N] >> 56n)]
)

export abstract class Kalyna implements Cipher {
    /** Block size */
    readonly blockSize: number;
    /** Key size */
    readonly keySize: number;

    private erk!: TArg<BigUint64Array>;
    private drk!: TArg<BigUint64Array>;
    private readonly numRounds: number;
    private readonly glOffset: number;
    private wordOffsets: number[];

    /** Kalyna abstract class */
    constructor(key: TArg<Uint8Array>, public readonly N: number, isDouble: boolean = false) {
        if(N < 2 || (N & (N - 1)) !== 0) throw new Error("N must be power of 2 and >= 2");
        this.blockSize = N << 3;
        this.keySize = this.blockSize;
        if(isDouble) this.keySize *= 2;
        if (key.length !== this.keySize) throw new Error("Invalid key length");

        this.wordOffsets = Array.from({length: 8}, (_, j) => Math.floor(j * this.N / 8));
        const X = 6 + 4 * Math.log2(N) + (isDouble ? 4 : 0);
        this.numRounds = X - (N > 2 || isDouble ? 1 : 0);
        this.glOffset = X * N;
        this.expandKey(key);
    }

    private expandKey(key: TArg<Uint8Array>) {
        const log2N = Math.log2(this.N),
            isDoubleKey = (this.keySize === this.blockSize * 2),
            R = isDoubleKey ? (6 + 2 * log2N) : (4 + 2 * log2N),
            rk = new BigUint64Array(R * this.N * 2),
            ks = new BigUint64Array(this.N), ksc = new BigUint64Array(this.N),
            t1 = new BigUint64Array(this.N), t2 = new BigUint64Array(this.N);
        t1[0] = isDoubleKey ? BigInt(2 * this.N + 2 * log2N + 1) : BigInt(2 * this.N + 1);

        const keys = bytesToUint64sLE(key);
        let k = new BigUint64Array(isDoubleKey ? this.N * 2 : this.N);
        const _0 = new BigUint64Array(this.N)

        if (isDoubleKey) {
            const ka = keys.subarray(0, this.N);
            this.addkey(t1, t2, ka);
            this.G(t2, t1, keys.subarray(this.N));
            this.GL(t1, t2, ka);
            this.G(t2, ks, _0);
            k.set(keys);
        } else {
            k.set(keys.subarray(0, this.N));
            this.addkey(t1, t2, keys);
            this.G(t2, t1, keys);
            this.GL(t1, t2, keys);
            this.G(t2, ks, _0);
        }

        let constant = 0x0001000100010001n;
        for (let i = 0; i < R; i++) {
            const offset = i * (this.N * 2);
        
            if (i > 0) {
                if (!isDoubleKey) swap_block(k, this.N);
                else if (i % 2 === 0) swap_block(k, this.N * 2);
            }
        
            const keySource = isDoubleKey
                ? (i % 2 === 0 ? k.subarray(0, this.N) : k.subarray(this.N))
                : k;
            for(let i = 0; i < this.N; i++) ksc[i] = ks[i] + constant;
            this.addkey(keySource, t2, ksc);
            this.G(t2, t1, ksc);
            this.GL(t1, rk.subarray(offset), ksc);
        
            if (i < R - 1) this.makeOddKey(
                rk.subarray(offset),
                rk.subarray(offset + this.N)
            );
            constant <<= 1n;
        }

        this.erk = rk.slice();
        for (let i = ((R * 2 - 3) * this.N); i > 0; i -= this.N)
            this.IMC(rk.subarray(i));
        this.drk = rk;
    }

    private makeOddKey(evenkey: TArg<BigUint64Array>, oddkey: TArg<BigUint64Array>) {
        const offset = 2 * this.N + 3;
        const evenkeys = uint64sToBytesLE(evenkey);
        const oddkeys = uint64sToBytesLE(oddkey);

        oddkeys.set(evenkeys.subarray(offset, this.blockSize));
        oddkeys.set(evenkeys.subarray(0, offset), this.blockSize - offset);
        oddkey.set(bytesToUint64sLE(oddkeys));
    }

    private addkey(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) y[i] = x[i] + k[i];
    }

    private subkey(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) y[i] = x[i] - k[i];
    }

    private column(x: TArg<BigUint64Array>, i: number): bigint {
        return column(
            x, i, this.N,
            this.wordOffsets[1], this.wordOffsets[2], this.wordOffsets[3],
            this.wordOffsets[4], this.wordOffsets[5], this.wordOffsets[6], this.wordOffsets[7]
        );
    }

    private G(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) y[i] = k[i] ^ this.column(x, i);
    }

    private GL(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) y[i] = k[i] + this.column(x, i);
    }

    private IMC(x: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) x[i] = IT[0][S[0][byte(x[i])]] ^
            IT[1][S[1][byte(x[i] >> 8n)]] ^
            IT[2][S[2][byte(x[i] >> 16n)]] ^
            IT[3][S[3][byte(x[i] >> 24n)]] ^
            IT[4][S[0][byte(x[i] >> 32n)]] ^
            IT[5][S[1][byte(x[i] >> 40n)]] ^
            IT[6][S[2][byte(x[i] >> 48n)]] ^
            IT[7][S[3][byte(x[i] >> 56n)]];
    }

    private IG(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) y[i] = k[i] ^
            IT[0][byte(x[(i + this.wordOffsets[0]) % this.N])] ^
            IT[1][byte(x[(i + this.wordOffsets[1]) % this.N] >> 8n)] ^
            IT[2][byte(x[(i + this.wordOffsets[2]) % this.N] >> 16n)] ^
            IT[3][byte(x[(i + this.wordOffsets[3]) % this.N] >> 24n)] ^
            IT[4][byte(x[(i + this.wordOffsets[4]) % this.N] >> 32n)] ^
            IT[5][byte(x[(i + this.wordOffsets[5]) % this.N] >> 40n)] ^
            IT[6][byte(x[(i + this.wordOffsets[6]) % this.N] >> 48n)] ^
            IT[7][byte(x[(i + this.wordOffsets[7]) % this.N] >> 56n)];
    }

    private IGL(x: TArg<BigUint64Array>, y: TArg<BigUint64Array>, k: TArg<BigUint64Array>) {
        for (let i = 0; i < this.N; i++) {
            let result = BigInt(IS[0][byte(x[(i + this.wordOffsets[0]) % this.N])]);
            result ^= BigInt(IS[1][byte(x[(i + this.wordOffsets[1]) % this.N] >> 8n)]) << 8n;
            result ^= BigInt(IS[2][byte(x[(i + this.wordOffsets[2]) % this.N] >> 16n)]) << 16n;
            result ^= BigInt(IS[3][byte(x[(i + this.wordOffsets[3]) % this.N] >> 24n)]) << 24n;
            result ^= BigInt(IS[0][byte(x[(i + this.wordOffsets[4]) % this.N] >> 32n)]) << 32n;
            result ^= BigInt(IS[1][byte(x[(i + this.wordOffsets[5]) % this.N] >> 40n)]) << 40n;
            result ^= BigInt(IS[2][byte(x[(i + this.wordOffsets[6]) % this.N] >> 48n)]) << 48n;
            result ^= BigInt(IS[3][byte(x[(i + this.wordOffsets[7]) % this.N] >> 56n)]) << 56n;

            y[i] = result - k[i];
        }
    }

    /** Encrypt block */
    encrypt(block: TArg<Uint8Array>): TRet<Uint8Array> {
        if(block.length != this.blockSize)
            throw new Error(`Incorrect length (need - ${this.blockSize}, got - ${block.length})`);
        const t1 = new BigUint64Array(this.N), t2 = new BigUint64Array(this.N);
        this.addkey(bytesToUint64sLE(block), t1, this.erk);

        for (let i = 0; i < this.numRounds; i++) {
            const roundKey = this.erk.subarray(this.N + i * this.N);
            if (i % 2 === 0) this.G(t1, t2, roundKey);
            else this.G(t2, t1, roundKey);
        }

        this.GL(t2, t1, this.erk.subarray(this.glOffset));
        return uint64sToBytesLE(t1);
    }

    /** Decrypt block */
    decrypt(block: TArg<Uint8Array>): TRet<Uint8Array> {
        if(block.length != this.blockSize)
            throw new Error(`Incorrect length (need - ${this.blockSize}, got - ${block.length})`);
        const t1 = new BigUint64Array(this.N), t2 = new BigUint64Array(this.N);
        this.subkey(bytesToUint64sLE(block), t1, this.drk.subarray(this.glOffset));
        this.IMC(t1);

        for (let i = 0; i < this.numRounds; i++) {
            const roundKey = this.drk.subarray(this.glOffset - this.N - i * this.N);
            if (i % 2 === 0) this.IG(t1, t2, roundKey);
            else this.IG(t2, t1, roundKey);
        }

        this.IGL(t2, t1, this.drk);
        return uint64sToBytesLE(t1);
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