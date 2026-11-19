import { type TArg, type TRet, copyBytes } from "@noble/hashes/utils.js";

const gf256Tables = /* @__PURE__ */ (() => {
    const exp = new Uint8Array(510),
        log = new Uint8Array(256);

    let x = 1;
    for (let i = 0; i < 255; i++) {
        exp[i] = x;
        log[x] = i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11D;
    }
    for (let i = 255; i < 510; i++) exp[i] = exp[i - 255];

    return { exp, log }
})();

export const gf256Multiply = (a: number, b: number): number => a === 0 || b === 0
    ? 0
    : gf256Tables.exp[gf256Tables.log[a] + gf256Tables.log[b]];

const POLY = [
    [0x87],
    [0x25, 0x04],
    [0x25, 0x01]
];

export const getGf2mReductionBytes = (blockSize: number): number[] => POLY[Math.log2(blockSize) - 4];

export const gf2mMultiply = (blockSize: number, a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const temp = copyBytes(a),
        result = new Uint8Array(blockSize),
        reductionBytes = getGf2mReductionBytes(blockSize);
    for (let i = 0; i < blockSize * 8; i++) {
        const byteIndex = Math.floor(i / 8);
        const bitIndex = i % 8;
        if (byteIndex < b.length && (b[byteIndex] & (1 << bitIndex))) for (let j = 0; j < blockSize; j++) result[j] ^= temp[j];
      
        let carry = 0;
        for (let j = 0; j < blockSize; j++) {
            const nextCarry = (temp[j] & 0x80) ? 1 : 0;
            temp[j] = ((temp[j] << 1) & 0xFF) | carry;
            carry = nextCarry;
        }
      
        if (carry) {
            for (let j = 0; j < reductionBytes.length; j++) if (j < blockSize) temp[j] ^= reductionBytes[j];
        }
    }
    
    return result;
}

export const gf2mDouble = (blockSize: number, a: TArg<Uint8Array>): TRet<Uint8Array> => {
    const result = copyBytes(a);
    const reductionBytes = getGf2mReductionBytes(blockSize);

    let carry = 0;
    for (let j = 0; j < blockSize; j++) {
        const nextCarry = (result[j] & 0x80) ? 1 : 0;
        result[j] = ((result[j] << 1) & 0xFF) | carry;
        carry = nextCarry;
    }
    if (carry) {
        for (let j = 0; j < reductionBytes.length; j++)
            if (j < blockSize) result[j] ^= reductionBytes[j];
    }

    return result;
}