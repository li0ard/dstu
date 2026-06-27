import type { TArg, TRet } from "@noble/hashes/utils.js";

export const pad = (data: TArg<Uint8Array>, blockSize: number): TRet<Uint8Array> => {
    const remainder = data.length % blockSize;
    if (remainder === 0) return data as TRet<Uint8Array>;

    const padLength = blockSize - remainder;
    const padded = new Uint8Array(data.length + padLength);
    padded.set(data);
    padded[data.length] = 0x80;

    return padded;
}

export const unpad = (paddedData: TArg<Uint8Array>, blockSize: number): TRet<Uint8Array> => {
    if (paddedData.length % blockSize !== 0)
        throw new Error("Padded data length must be multiple of block size");

    let i = paddedData.length - 1;
    while (i >= 0 && paddedData[i] === 0) i--;

    if (i < 0) throw new Error("Padding error: all bytes are zero");
    if (i === paddedData.length - 1)throw new Error("Padding error: no padding bytes found");

    return paddedData.slice(0, i + 1);
}