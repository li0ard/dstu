import { bytesToNumberBE, bytesToNumberLE, numberToBytesBE, numberToBytesLE, type TArg, type TRet } from "@noble/curves/utils.js";
import { copyBytes } from "@noble/hashes/utils.js";

export const xorBytes = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const mlen = Math.min(a.length, b.length);
    const result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}

export const bytesToUint64sBE = (b: TArg<Uint8Array>): TRet<BigUint64Array> => {
    const size = Math.floor(b.length / 8);
    const result = new BigUint64Array(size);
    
    for (let i = 0; i < size; i++) result[i] = bytesToNumberBE(b.subarray(i * 8, i * 8 + 8));
    return result;
}

export const uint64sToBytesBE = (w: TArg<BigUint64Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(w.length * 8);
    for (let i = 0; i < w.length; i++) result.set(numberToBytesBE(w[i], 8), i * 8);
    return result;
}

export const bytesToUint64sLE = (b: TArg<Uint8Array>): TRet<BigUint64Array> => {
    const size = Math.floor(b.length / 8);
    const result = new BigUint64Array(size);
    
    for (let i = 0; i < size; i++) result[i] = bytesToNumberLE(b.subarray(i * 8, i * 8 + 8));
    return result;
}

export const uint64sToBytesLE = (w: TArg<BigUint64Array>): TRet<Uint8Array> => {
    const result = new Uint8Array(w.length * 8);
    for (let i = 0; i < w.length; i++) result.set(numberToBytesLE(w[i], 8), i * 8);
    return result;
}


export const byte = (a: bigint) => Number(a & 0xFFn);

export const getGf2mReductionBytes = (blockSize: number): number[] => [
    [0x87],
    [0x25, 0x04],
    [0x25, 0x01]
][Math.log2(blockSize) - 4];

export const gf2mMul = (blockSize: number, a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const temp = copyBytes(a);
    const result = new Uint8Array(blockSize);
    
    const reductionBytes = getGf2mReductionBytes(blockSize);
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