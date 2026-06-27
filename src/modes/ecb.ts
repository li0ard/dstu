import type { TArg, TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import type { BlockMode } from "../types.js";

/** Electronic Codebook (ECB) mode */
export const ecb = (cipher: Kalyna): BlockMode => {
    const encrypter = cipher.encrypt.bind(cipher);
    const decrypter = cipher.decrypt.bind(cipher);

    const core = (crypter: (msg: TArg<Uint8Array>) => TRet<Uint8Array>, data: TArg<Uint8Array>): TRet<Uint8Array> => {
        if (data.length == 0 || data.length % cipher.blockSize !== 0)
            throw new Error("Data not aligned");

        const output = new Uint8Array(data.length);
        for(let i = 0; i < data.length; i += cipher.blockSize)
            output.set(crypter(data.subarray(i, i + cipher.blockSize)), i);

        return output;
    }

    return {
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => core(encrypter, plaintext),
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => core(decrypter, ciphertext),
    }
}