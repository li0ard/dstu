import { concatBytes, createView, type TArg, type TRet } from "@noble/hashes/utils.js";
import { DKE_1, keySequences } from "./const.js";
import type { Cipher } from "../types.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";

const G = (v: number, sbox: TArg<Uint8Array>): number => {
    const nibble = (r: number, i: number): number => {
        const b = sbox[r + (i >> 1)];
        return (i & 1) == 0 ? (b >>> 4) : (b & 0x0f);
    }

    const t = (nibble(0, v & 0x0f) << 0) |
        (nibble(8, (v >> 4) & 0x0f) << 4) |
        (nibble(16, (v >> 8) & 0x0f) << 8) |
        (nibble(24, (v >> 12) & 0x0f) << 12) |
        (nibble(32, (v >> 16) & 0x0f) << 16) |
        (nibble(40, (v >> 20) & 0x0f) << 20) |
        (nibble(48, (v >> 24) & 0x0f) << 24) |
        (nibble(56, (v >> 28) & 0x0f) << 28);

    return ((t << 11) | (t >>> 21)) >>> 0;
}

const extendKey = (key: TArg<Uint8Array>, sequence: number[]): TRet<Uint32Array> => {
    const view = createView(key);
    const result = new Uint32Array(sequence.length);
    
    for (let i = 0; i < sequence.length; i++)
        result[i] = view.getUint32(sequence[i] * 4, true);
    
    return result;
}

/** DSTU 9311:2024 cipher (Revised DSTU GOST 28147:2009) */
export class Dstu9311 implements Cipher {
    readonly keySize = 32;
    readonly blockSize = 8;

    /** DSTU 9311:2024 cipher (Revised DSTU GOST 28147:2009) */
    constructor(
        private key: TArg<Uint8Array>,
        private sbox: TArg<Uint8Array> = DKE_1,
    ) {
        if (key.length !== this.keySize) throw new Error("Invalid key length");
    }

    proceedBlock(block: TArg<Uint8Array>, sequence: number[]): TRet<Uint8Array> {
        if (block.length !== this.blockSize) throw new Error("Invalid block size");
        const roundKeys = extendKey(this.key, sequence);
        
        let a0 = Number(bytesToNumberLE(block.subarray(4,8))),
            a1 = Number(bytesToNumberLE(block.subarray(0,4)));
        for (let i = 0; i < roundKeys.length; i++) {
            const temp = a1;
            a1 = (a0 ^ G((a1 + roundKeys[i]) >>> 0, this.sbox)) >>> 0;
            a0 = temp;
        }

        return concatBytes(numberToBytesLE(a0, 4), numberToBytesLE(a1, 4));
    }

    encrypt(plaintext: TArg<Uint8Array>): TRet<Uint8Array> {
        return this.proceedBlock(plaintext, keySequences.ENCRYPT);
    }

    decrypt(ciphertext: TArg<Uint8Array>): TRet<Uint8Array> {
        return this.proceedBlock(ciphertext, keySequences.DECRYPT);
    }
}

export * from "./const.js";
export * from "./hash.js";