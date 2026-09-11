import { concatBytes, randomBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { Kalyna256 } from "./kalyna/index.js";
import { cfb, cmac } from "./modes/index.js";
import { equalBytes } from "@noble/curves/utils.js";
import { Dstu9311 } from "./dstu9311/index.js";

const IV1_KALYNA = new Uint8Array([
    0x69, 0x73, 0x27, 0x1D, 0x6E, 0x61, 0x1D, 0x06, 0x61, 0x67, 0x15, 0x04, 0x6C, 0x65, 0x50, 0x4C,
    0x20, 0x20, 0x00, 0x4F, 0x6D, 0x68, 0x01, 0x1F, 0x65, 0x61, 0x0C, 0x0C, 0x73, 0x73, 0x47, 0x14
]);

const IV1_9311 = new Uint8Array([
    0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05
]);

/** Key wrap (`Dstu7624Wrap`/`GOST28147Wrap`) */
export const keyWrap = (kek: TArg<Uint8Array>, useDstu9311 = false): {
    wrap: (key: TArg<Uint8Array>, iv?: TArg<Uint8Array>) => TRet<Uint8Array>,
    unwrap: (wrappedKey: TArg<Uint8Array>) => TRet<Uint8Array>,
} => {
    if(kek.length != 32) throw new Error("Invalid key length");
    const cipher = new (useDstu9311 ? Dstu9311 : Kalyna256)(kek);
    const ivLength = useDstu9311 ? 8 : 32,
        macLength = useDstu9311 ? 4 : 32;

    const macMode = cmac(cipher, macLength);
    const finalMode = cfb(cipher, useDstu9311 ? IV1_9311 : IV1_KALYNA, 32);

    return Object.freeze({
        wrap: (key: TArg<Uint8Array>, iv?: TArg<Uint8Array>): TRet<Uint8Array> => {
            iv ??= randomBytes(ivLength);
            if(iv.length != ivLength) throw new Error("Invalid IV length");
            const mac = macMode.compute(key);

            return finalMode.encrypt(
                concatBytes(iv, cfb(cipher, iv, 32).encrypt(concatBytes(key, mac))).reverse()
            );
        },
        unwrap: (wrappedKey: TArg<Uint8Array>): TRet<Uint8Array> => {
            const dec_wrapped = finalMode.decrypt(wrappedKey).reverse();
            const iv = dec_wrapped.subarray(0, ivLength);
            const key_mac = cfb(cipher, iv, 32).decrypt(dec_wrapped.subarray(ivLength));
            const key = key_mac.slice(0, -macLength), mac = key_mac.subarray(-macLength);

            const actualMac = macMode.compute(key);
            if(!equalBytes(actualMac, mac)) throw new Error("Invalid MAC");

            return key;
        }
    });
}