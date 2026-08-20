import { concatBytes, copyBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { Kalyna } from "../kalyna/index.js";
import { pad } from "../padding.js";
import { gf2mMul, xorBytes } from "../utils.js";
import type { GMACMode, MACMode } from "../types.js";
import { numberToBytesLE } from "@noble/curves/utils.js";

/** Message Authentication Code (MAC) mode */
export const cmac = (cipher: Kalyna, q = 16): MACMode => Object.freeze({
    compute: (msg: TArg<Uint8Array>): TRet<Uint8Array> => {
        let data = copyBytes(msg);
        const zeroBlock = new Uint8Array(cipher.blockSize);
        if(data.length % cipher.blockSize !== 0) {
            data = pad(data, cipher.blockSize);
            zeroBlock[0] = 1;
        }

        const Kd = cipher.encrypt(zeroBlock);
        let c = new Uint8Array(cipher.blockSize);
        const numBlocks = data.length / cipher.blockSize;
        for (let i = 0; i < numBlocks - 1; i++) {
            const blockStart = i * cipher.blockSize;        
            c = cipher.encrypt(xorBytes(c, data.subarray(blockStart, blockStart + cipher.blockSize)));
        }

        const lastBlockStart = (numBlocks - 1) * cipher.blockSize;
        c = cipher.encrypt(xorBytes(xorBytes(c, data.subarray(lastBlockStart, lastBlockStart + cipher.blockSize)), Kd));

        return c.slice(0, q);
    }
});

/** Galois Message Authentication Code (GMAC) mode */
export const gmac = (cipher: Kalyna, q = 16): GMACMode => Object.freeze({
    compute: (aad: TArg<Uint8Array>, msg: TArg<Uint8Array>): TRet<Uint8Array> => {
        const blockSize = cipher.blockSize;
        const H = cipher.encrypt(new Uint8Array(blockSize));

        let B: Uint8Array = new Uint8Array(blockSize);
        let i = 0;
        while (i < aad.length) {
            const blockSizeToProcess = Math.min(blockSize, aad.length - i);
            const block = new Uint8Array(blockSize);

            for (let j = 0; j < blockSizeToProcess; j++) block[j] = aad[i + j];
            if (blockSizeToProcess < blockSize) block[blockSizeToProcess] = 0x80; 
            for (let j = 0; j < blockSize; j++) B[j] ^= block[j];
            B = gf2mMul(blockSize, B, H);
        
            i += blockSize;
        }

        i = 0;
        while (i < msg.length) {
            const blockSizeToProcess = Math.min(blockSize, msg.length - i);
            const block = new Uint8Array(blockSize);
        
            for (let j = 0; j < blockSizeToProcess; j++) block[j] = msg[i + j];
            if (blockSizeToProcess < blockSize) block[blockSizeToProcess] = 0x80; 
            for (let j = 0; j < blockSize; j++) B[j] ^= block[j];
            B = gf2mMul(blockSize, B, H);
        
            i += blockSize;
        }

        B = xorBytes(B, concatBytes(
            numberToBytesLE(aad.length * 8, blockSize / 2),
            numberToBytesLE(msg.length * 8, blockSize / 2)
        ));

        return cipher.encrypt(B).slice(0, q);
    }
});