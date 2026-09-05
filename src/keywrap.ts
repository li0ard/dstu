import { concatBytes, randomBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Kalyna256 } from "./kalyna/index.js";
import { cfb, cmac } from "./modes/index.js";
import { equalBytes } from "@noble/curves/utils.js";

const IV1 = new Uint8Array([
    0x69, 0x73, 0x27, 0x1D, 0x6E, 0x61, 0x1D, 0x06, 0x61, 0x67, 0x15, 0x04, 0x6C, 0x65, 0x50, 0x4C,
    0x20, 0x20, 0x00, 0x4F, 0x6D, 0x68, 0x01, 0x1F, 0x65, 0x61, 0x0C, 0x0C, 0x73, 0x73, 0x47, 0x14
]);

/** Key wrap with Kalyna (`Dstu7624Wrap`) */
export const keywrap = (kek: TArg<Uint8Array>): {
    wrap: (key: TArg<Uint8Array>, iv?: TArg<Uint8Array>) => TRet<Uint8Array>,
    unwrap: (wrappedKey: TArg<Uint8Array>) => TRet<Uint8Array>,
} => {
    if(kek.length != 32) throw new Error("Invalid key length");
    const cipher = new Kalyna256(kek);

    return Object.freeze({
        wrap: (key: TArg<Uint8Array>, iv?: TArg<Uint8Array>): TRet<Uint8Array> => {
            iv ??= randomBytes(32);
            if(iv.length != 32) throw new Error("Invalid IV length");
            const mac = cmac(cipher, 32).compute(key);
            const mode = cfb(cipher, iv, 32);

            return cfb(cipher, IV1, 32).encrypt(
                concatBytes(iv, mode.encrypt(concatBytes(key, mac))).reverse()
            );
        },
        unwrap: (wrappedKey: TArg<Uint8Array>): TRet<Uint8Array> => {
            const dec_wrapped = cfb(cipher, IV1, 32).decrypt(wrappedKey).reverse();
            const iv = dec_wrapped.subarray(0, 32);
            const key_mac = cfb(cipher, iv, 32).decrypt(dec_wrapped.subarray(32));
            const key = key_mac.slice(0, 32), mac = key_mac.subarray(32);

            const actualMac = cmac(cipher, 32).compute(key);
            if(!equalBytes(actualMac, mac)) throw new Error("Invalid MAC");

            return key;
        }
    });
}