import type { TArg, TRet } from "@noble/hashes/utils.js";
import BN from "bn.js";
import { be2LEw, bn2LE, invertWords, le2BN, modWords, mulWords, SQR_PRECOMP, WORD_BITS } from "./utils.js";

const numWordsFor = (x: BN): number => 
    Math.max(1, Math.ceil(Math.max(x.bitLength(), 1) / WORD_BITS));

/** Compute curve modulo */
export const computeMod = (m: number, ks: number[]): BN => {
    const modulo = new BN(0);
    modulo.setn(m, 1);
    modulo.setn(0, 1);
    for(const i of ks) modulo.setn(i, 1);

    return modulo;
}

/** Create `GF(2^m)` field */
export const createField = (m: number, ks: number[]) => {
    const modulo = computeMod(m, ks),
        wordsPerElement = Math.ceil(m / WORD_BITS),
        wordsForModWord = Math.floor(m / WORD_BITS) + 1;
    const polyBits = Int32Array.from([m, ...[...ks].sort((a, b) => b - a), 0]),
        polyWordsForInv = bn2LE(modulo, wordsForModWord);

    const mod = (f: BN): BN => {
        if(f.bitLength() <= m) return f.clone();
        const words = bn2LE(f, Math.ceil(f.bitLength() / WORD_BITS));

        return le2BN(modWords(words, polyBits).subarray(0, wordsPerElement));
    }

    const mul = (x: BN, v: BN): BN => {
        if(x.eq(v)) return sqr(x);
        const xw = bn2LE(x, numWordsFor(x)),
            vw = bn2LE(v, numWordsFor(v));

        return le2BN(modWords(mulWords(xw, vw), polyBits).subarray(0, wordsPerElement));
    }

    const div = (x: BN, v: BN): BN => mul(x, invert(v));

    const sqr = (x: BN): BN => {
        const bytes = x.toArray();
        const out = new Uint8Array(bytes.length * 2);
        for(let i = 0; i < bytes.length; i++) {
            const v = SQR_PRECOMP[bytes[i]];
            out[2 * i] = (v >> 8) & 0xff;
            out[2 * i + 1] = v & 0xff;
        }

        const words = be2LEw(out, Math.max(1, Math.ceil(out.length / 4)));
        return le2BN(modWords(words, polyBits).subarray(0, wordsPerElement));
    }

    const testBit = (x: BN, i: number): 0 | 1 => x.testn(i) ? 1 : 0;
    const invBit = (x: BN, i: number) => x.setn(i, !x.testn(i));

    const sqrt = (x: BN): BN => {
        let r = mod(x);
        for(let i = 0; i < m - 1; i++) r = sqr(r);
        return r;
    }

    const trace = (x: BN): 0 | 1 => {
        let t = x;
        for(let i = 1; i < m; i++) t = sqr(t).ixor(x);
        return testBit(t, 0);
    }

    const traceOnb = (x: BN): 0 | 1 => {
        let t = 0;
        for(let i = 0; i < m; i++) t ^= testBit(x, i);
        return t as 0 | 1;
    }

    const htrace = (x: BN): BN => {
        let ht = x;
        for(let i = 1; i <= Math.floor((m - 1) / 2); i++) ht = sqr(sqr(ht)).ixor(x);
        return ht;
    }

    const invert = (f: BN): BN => {
        const reducedWords = modWords(bn2LE(f, numWordsFor(f)), polyBits),
            aWords = new Uint32Array(wordsForModWord);
        aWords.set(reducedWords.subarray(0, Math.min(reducedWords.length, wordsForModWord)));

        return le2BN(invertWords(aWords, polyWordsForInv, wordsForModWord).subarray(0, wordsPerElement));
    }

    const solve_quad = (v: BN): BN => {
        const a = mod(v), z = htrace(a);
        if(sqr(z).ixor(z).cmp(a) == 0) return mod(z);

        throw new Error("squad eq fail: no square root exists");
    }

    const hashToField = (hash: TArg<Uint8Array>): BN => {
        const h = new BN(hash);
        return h.imaskn(Math.min(m, h.bitLength()));
    }

    const fromHexStringOrBytes = (v: string | Uint8Array): BN => new BN(v, 16);
    const toBytes = (x: BN, length?: number): TRet<Uint8Array> => new Uint8Array(x.toArray("be", length));

    return Object.freeze({
        MODULO: modulo, LENGTH: Math.ceil(m/8),
        mod, mul, div, sqr, sqrt, invert,
        solve_quad, trace, traceOnb, hashToField, invBit,
        fromHexStringOrBytes, toBytes
    });
}

export * from "./onb.js";
