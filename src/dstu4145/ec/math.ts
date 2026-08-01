import type { TArg, TRet } from "@noble/hashes/utils.js";
import BN from "bn.js";

/** Compute curve modulo */
export const computeMod = (m: number, ks: number[]): BN => {
    const modulo = new BN(0);
    modulo.setn(m, 1);
    modulo.setn(0, 1);
    for (const i of ks) modulo.setn(i, 1);

    return modulo;
}

/** Create GF(2^m) fields */
export const createField = (m: number, ks: number[]) => {
    const modulo = computeMod(m, ks);
    const mod = (f: BN): BN => {
        const cmp = f.cmp(modulo);
        if (cmp === 0) return new BN(0);
        if (cmp < 0) return f.clone();

        let bag = f;
        const vl = modulo.bitLength();
        while (true) {
            bag = bag.xor(modulo.ushln(bag.bitLength() - vl));
            if (bag.bitLength() < vl) return bag;
        }
    }

    const mul = (x: BN, v: BN): BN => {
        let bag = new BN(0);
        let shift = x;
        const vLen = v.bitLength();

        for (let i = 0; i < vLen; i++) {
            if (v.testn(i)) bag = bag.xor(shift);
            shift = shift.ushln(1);
        }

        return mod(bag);
    }

    // Might be optimized in future
    const sqr = (x: BN): BN => mul(x,x);

    const testBit = (x: BN, i: number): 0 | 1 => x.testn(i) ? 1 : 0;
    const setBit = (x: BN, i: number, v: number): BN => x.setn(i, v == 1);

    const shiftLeft = (x: BN, n: number): BN => {
        if (n < 0) throw new Error("Shift amount cannot be negative.");
        return x.ushln(n);
    }

    const trace = (x: BN): 0 | 1 => {
        let t = x;
        for (let i = 1; i < m; i++) t = sqr(t).xor(x);
        return testBit(t, 0);
    }

    const traceOnb = (x: BN): 0 | 1 => {
        let t = 0;
        for (let i = 0; i < m; i++) t ^= testBit(x, i);
        return t as 0 | 1;
    }

    const invert = (f: BN): BN => {
        let r = mod(f), s = modulo;
        let u = new BN(1), v = new BN(0);

        while (r.bitLength() > 1) {
            let j = s.bitLength() - r.bitLength();
            if (j < 0) {
                [r, s] = [s, r];
                [u, v] = [v, u];
                j = -j;
            }
            s = s.xor(shiftLeft(r, j));
            v = v.xor(shiftLeft(u, j));
        }
        return u;
    }

    const sqrt = (v: BN): BN => {
        const range_to = Math.floor((m - 1) / 2);
        const a = mod(v);

        let z = a.clone();
        for (let idx = 1; idx <= range_to; idx++) {
            z = sqr(sqr(z)).xor(a);
        }

        const w = sqr(z).xor(z);
        if (w.cmp(a) == 0) return mod(z);
        throw new Error("squad eq fail: no square root exists");
    }

    const hashToField = (hash: TArg<Uint8Array>): BN => {
        const bn = new BN(hash);
        const k = Math.min(m, bn.bitLength());
        return bn.maskn(k);
    }

    const fromHexStringOrBytes = (v: string | Uint8Array): BN => new BN(v, 16);
    const toBytes = (x: BN, length?: number): TRet<Uint8Array> => new Uint8Array(x.toArray("be", length));

    return Object.freeze({
        MODULO: modulo,
        LENGTH: Math.ceil(m/8),
        mod, mul, sqr, testBit, setBit, shiftLeft, trace, traceOnb, invert, sqrt,
        fromHexStringOrBytes, toBytes, hashToField
    });
}