import { abytes, createView, type TArg, type TRet } from "@noble/hashes/utils.js";
import { DKE_1, keySequences } from "./const.js";
import type { Cipher } from "../types.js";

const nibble = (sbox: TArg<Uint8Array>, r: number, i: number): number => {
    const b = sbox[(r << 3) + (i >> 1)];
    return (i & 1) === 0 ? (b >>> 4) : (b & 0x0f);
}

const genTable = (sbox: TArg<Uint8Array>): TRet<Uint32Array> => {
    const table = new Uint32Array(4 * 256);
    for (let k = 0; k < 4; k++) {
        for (let v = 0; v < 256; v++) {
            const x = ((nibble(sbox, 2 * k + 1, v >> 4) << 4) | nibble(sbox, 2 * k, v & 15)) << (8 * k);
            table[(k << 8) | v] = (x << 11) | (x >>> 21);
        }
    }
    return table;
}

const TABLES = new WeakMap<Uint8Array, Uint32Array>();
const getTable = (sbox: TArg<Uint8Array>): TRet<Uint32Array> => {
    let t = TABLES.get(sbox);
    if (!t) TABLES.set(sbox, t = genTable(sbox));
    return t as TRet<Uint32Array>;
}

const G = (v: number, t: TArg<Uint32Array>): number =>
    t[v & 0xff] ^ t[256 + ((v >>> 8) & 0xff)] ^
    t[512 + ((v >>> 16) & 0xff)] ^ t[768 + (v >>> 24)];

/** DSTU 9311:2024 cipher (Revised DSTU GOST 28147:2009) */
export class Dstu9311 implements Cipher {
    readonly keySize = 32;
    readonly blockSize = 8;

    private rk = new Uint32Array(8);

    /** DSTU 9311:2024 cipher (Revised DSTU GOST 28147:2009) */
    constructor(
        private key: TArg<Uint8Array>,
        private sbox: TArg<Uint8Array> = DKE_1,
    ) {
        abytes(key, this.keySize, "key");
        abytes(sbox, 64, "sbox");

        const view = createView(key);
        for (let i = 0; i < 8; i++) this.rk[i] = view.getUint32(i * 4, true);
    }

    proceedBlock(block: TArg<Uint8Array>, sequence: number[]): TRet<Uint8Array> {
        abytes(block, this.blockSize, "block");
        const inView = createView(block),
            t = getTable(this.sbox);
        let a0 = inView.getUint32(4, true),
            a1 = inView.getUint32(0, true);
        for (let i = 0; i < sequence.length; i++) {
            const temp = a1;
            a1 = (a0 ^ G((a1 + this.rk[sequence[i]]) >>> 0, t)) >>> 0;
            a0 = temp;
        }

        const out = new Uint8Array(this.blockSize),
            outView = createView(out);
        outView.setUint32(0, a0, true);
        outView.setUint32(4, a1, true);

        return out;
    }

    encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        return this.proceedBlock(plaintext, keySequences.ENCRYPT);
    }

    decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        return this.proceedBlock(ciphertext, keySequences.DECRYPT);
    }
}

export * from "./const.js";
export * from "./hash.js";