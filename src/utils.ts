import { abytes, anumber, type TArg, type TRet } from "@noble/hashes/utils.js";

export const _U32 = 0xFFFFFFFF,
    _NULL = /* @__PURE__ */ Uint8Array.of();

export const xorBytes = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const mlen = Math.min(a.length, b.length),
        result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}

export const xorBytesInPlace = (dst: TArg<Uint8Array>, src: TArg<Uint8Array>, off = 0) => {
    if (off + dst.length > src.length) throw new Error("src is too short");
    for(let i = 0; i < dst.length; i++) dst[i] ^= src[off + i];
}

export const reverseBytes = (
    bytes: TArg<Uint8Array>,
    from?: number,
    to?: number
): TRet<Uint8Array> => bytes.slice(from, to).reverse();

const atitle = (title: string): string => title ? `"${title}" ` : '';

export const abytesAligned = (
    value: TArg<Uint8Array>,
    blockSize: number,
    title: string = ""
): TRet<Uint8Array> => {
    abytes(value);
    anumber(blockSize);
    if (value.length !== 0 && value.length % blockSize === 0) return value as TRet<Uint8Array>;
    
    const ofLen = ` of length aligned to ${blockSize}`,
        got = `length=${value.length}`,
        message = atitle(title) + 'expected Uint8Array' + ofLen + ', got ' + got;
    throw new RangeError(message);
}

export const bytesToU32LE = (b: Uint8Array): Uint32Array => {
    const out = new Uint32Array(b.length >>> 2);
    for (let i = 0, j = 0; i < out.length; i++, j += 4)
        out[i] = b[j] | (b[j + 1] << 8) | (b[j + 2] << 16) | (b[j + 3] << 24);

    return out;
}

export const u32ToBytesLE = (w: Uint32Array): Uint8Array => {
    const out = new Uint8Array(w.length << 2);
    for (let i = 0, j = 0; i < w.length; i++, j += 4) {
        const v = w[i];
        out[j] = v;
        out[j + 1] = v >>> 8;
        out[j + 2] = v >>> 16;
        out[j + 3] = v >>> 24;
    }

    return out;
}