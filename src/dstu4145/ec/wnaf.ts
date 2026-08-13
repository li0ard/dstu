// Based on jkurwa
// github.com/dstucrypt/jkurwa

import BN from "bn.js";

const DEFAULT_CUTOFFS = [13, 41, 121, 337, 897, 2305];

export const bitLength = (n: number): number => n === 0 ? 0 : 32 - Math.clz32(n);

const compactNaf = (k: BN): Int32Array => {
    if(k.bitLength() >= (1 << 16)) throw new Error("'k' must have bitlength < 2^16");
    if(k.isZero()) return new Int32Array(0);

    const _3k = k.shln(1).add(k);
    const bits = _3k.bitLength();
    const naf = new Int32Array(bits >> 1);
    const diff = _3k.xor(k);

    const highBit = bits - 1;
    let length = 0, zeroes = 0;
    for (let i = 1; i < highBit; ++i) {
        if (!diff.testn(i)) {
            ++zeroes;
            continue;
        }

        const digit = k.testn(i) ? -1 : 1;
        naf[length++] = (digit << 16) | zeroes;
        zeroes = 1;
        ++i;
    }

    naf[length++] = (1 << 16) | zeroes;

    return naf.length > length ? naf.subarray(0, length) : naf;
}

export const windowNaf = (width: number, k: BN): Int32Array => {
    if(width === 2) return compactNaf(k);

    const bigint = k.clone();
    const retLen = Math.floor(bigint.bitLength() / width) + 1;
    const wnaf = new Int32Array(retLen);
    const pow2 = 1 << width,
        mask = pow2 - 1,
        sign = pow2 >>> 1;

    let carry = false;
    let length = 0, pos = 0;
    while(pos <= bigint.bitLength()) {
        if(bigint.testn(pos) === carry) {
            ++pos;
            continue;
        }

        bigint.iushrn(pos);

        let digit = bigint.andln(mask) as unknown as number;
        if(carry) digit++;

        carry = (digit & sign) !== 0;
        if(carry) digit -= pow2;

        const zeroes = length > 0 ? pos - 1 : pos;
        wnaf[length++] = (digit << 16) | zeroes;
        pos = width;
    }

    return wnaf.length > length ? wnaf.subarray(0, length) : wnaf;
}

export const getWindowSize = (bits: number): number => {
    let i = 0;
    for(; i < DEFAULT_CUTOFFS.length; ++i)
        if (bits < DEFAULT_CUTOFFS[i]) break;
    return i + 2;
}