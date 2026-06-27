import type { TArg, TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import { cbc_decrypt, cbc_encrypt } from "@li0ard/sp80038";
import type { BlockMode } from "../types.js";

/** Cipher Block Chaining (CBC) mode */
export const cbc = (cipher: Kalyna, iv: TArg<Uint8Array>): BlockMode => {
    const encrypter = cipher.encrypt.bind(cipher);
    const decrypter = cipher.decrypt.bind(cipher);

    return {
        encrypt: (plaintext: TArg<Uint8Array>): TRet<Uint8Array> => cbc_encrypt(encrypter,  cipher.blockSize, plaintext, iv),
        decrypt: (ciphertext: TArg<Uint8Array>): TRet<Uint8Array> => cbc_decrypt(decrypter,  cipher.blockSize, ciphertext, iv)
    }
}