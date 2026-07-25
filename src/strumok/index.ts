import type { TArg, TRet } from "@noble/hashes/utils.js";
import { ALPHA_MUL, ALPHA_MUL_INV, T as T_ } from "../const.js";
import { bytesToUint64sBE, byte } from "../utils.js";

const not = (w: bigint): bigint => {
    const MAX_UINT64 = (1n << 64n) - 1n;
    return MAX_UINT64 - (w & MAX_UINT64);
}

const a_mul = (w: bigint): bigint => (w << 8n) ^ (ALPHA_MUL[byte(w >> 56n)]);
const ainv_mul = (w: bigint): bigint => (w >> 8n) ^ (ALPHA_MUL_INV[byte(w)]);
const T = (w: bigint): bigint => (
    T_[0][byte(w)] ^
    T_[1][byte(w >> 8n)] ^
    T_[2][byte(w >> 16n)] ^
    T_[3][byte(w >> 24n)] ^
    T_[4][byte(w >> 32n)] ^
    T_[5][byte(w >> 40n)] ^
    T_[6][byte(w >> 48n)] ^
    T_[7][byte(w >> 56n)]
);

/** Strumok stream cipher */
export class Strumok {
    public readonly blockSize = 128;
    public readonly keySize: number;
    private S: BigUint64Array;
    private r: BigUint64Array;
    private key: BigUint64Array;
    private iv: BigUint64Array;

    /**
     * Strumok stream cipher
     * @param key Encryption key (256 or 512 bit)
     */
    constructor(key: TArg<Uint8Array>, iv: TArg<Uint8Array>) {
        if(iv.length !== 32) throw new Error("Unsupported IV length");
        this.key = bytesToUint64sBE(key);
        this.iv = bytesToUint64sBE(iv);
        this.keySize = key.length;
        this.S = new BigUint64Array(16);
        this.r = new BigUint64Array(2);

        if(this.keySize == 32) {
            this.S[0] = this.key[3] ^ this.iv[0];
            this.S[1] = this.key[2];
            this.S[2] = this.key[1] ^ this.iv[1];
            this.S[3] = this.key[0] ^ this.iv[2];
            this.S[4] = this.key[3];
            this.S[5] = this.key[2] ^ this.iv[3];
            this.S[6] = not(this.key[1]);
            this.S[7] = not(this.key[0]);
            this.S[8] = this.key[3];
            this.S[9] = this.key[2];
            this.S[10] = not(this.key[1]);
            this.S[11] = this.key[0];
            this.S[12] = this.key[3];
            this.S[13] = not(this.key[2]);
            this.S[14] = this.key[1];
            this.S[15] = not(this.key[0]);
        } else if(this.keySize == 64) {
            this.S[0] = this.key[7] ^ this.iv[0];
            this.S[1] = this.key[6];
            this.S[2] = this.key[5];
            this.S[3] = this.key[4] ^ this.iv[1];
            this.S[4] = this.key[3];
            this.S[5] = this.key[2] ^ this.iv[2];
            this.S[6] = this.key[1];
            this.S[7] = not(this.key[0]);
            this.S[8] = this.key[4] ^ this.iv[3];
            this.S[9] = not(this.key[6]);
            this.S[10] = this.key[5];
            this.S[11] = not(this.key[7]);
            this.S[12] = this.key[3];
            this.S[13] = this.key[2];
            this.S[14] = not(this.key[1]);
            this.S[15] = this.key[0];
        } else throw new Error("Unsupported key length");
        this.r[0] = 0n;
        this.r[1] = 0n;

        for (let i = 0; i < 2; i++) {
            let outfrom_fsm: bigint, fsmtmp: bigint;

            outfrom_fsm = (this.r[0] + this.S[15]) ^ this.r[1];
            this.S[0] = a_mul(this.S[0]) ^ this.S[13] ^ ainv_mul(this.S[11]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[13];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[0]) ^ this.r[1];
            this.S[1] = a_mul(this.S[1]) ^ this.S[14] ^ ainv_mul(this.S[12]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[14];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[1]) ^ this.r[1];
            this.S[2] = a_mul(this.S[2]) ^ this.S[15] ^ ainv_mul(this.S[13]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[15];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[2]) ^ this.r[1];
            this.S[3] = a_mul(this.S[3]) ^ this.S[0] ^ ainv_mul(this.S[14]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[0];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[3]) ^ this.r[1];
            this.S[4] = a_mul(this.S[4]) ^ this.S[1] ^ ainv_mul(this.S[15]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[1];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[4]) ^ this.r[1];
            this.S[5] = a_mul(this.S[5]) ^ this.S[2] ^ ainv_mul(this.S[0]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[2];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[5]) ^ this.r[1];
            this.S[6] = a_mul(this.S[6]) ^ this.S[3] ^ ainv_mul(this.S[1]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[3];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[6]) ^ this.r[1];
            this.S[7] = a_mul(this.S[7]) ^ this.S[4] ^ ainv_mul(this.S[2]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[4];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[7]) ^ this.r[1];
            this.S[8] = a_mul(this.S[8]) ^ this.S[5] ^ ainv_mul(this.S[3]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[5];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[8]) ^ this.r[1];
            this.S[9] = a_mul(this.S[9]) ^ this.S[6] ^ ainv_mul(this.S[4]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[6];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[9]) ^ this.r[1];
            this.S[10] = a_mul(this.S[10]) ^ this.S[7] ^ ainv_mul(this.S[5]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[7];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[10]) ^ this.r[1];
            this.S[11] = a_mul(this.S[11]) ^ this.S[8] ^ ainv_mul(this.S[6]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[8];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[11]) ^ this.r[1];
            this.S[12] = a_mul(this.S[12]) ^ this.S[9] ^ ainv_mul(this.S[7]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[9];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[12]) ^ this.r[1];
            this.S[13] = a_mul(this.S[13]) ^ this.S[10] ^ ainv_mul(this.S[8]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[10];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[13]) ^ this.r[1];
            this.S[14] = a_mul(this.S[14]) ^ this.S[11] ^ ainv_mul(this.S[9]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[11];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;

            outfrom_fsm = (this.r[0] + this.S[14]) ^ this.r[1];
            this.S[15] = a_mul(this.S[15]) ^ this.S[12] ^ ainv_mul(this.S[10]) ^ outfrom_fsm;
            fsmtmp = this.r[1] + this.S[12];
            this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;
        }
    }

    /** Generate next keystream */
    next_stream(): TRet<BigUint64Array> {
        let fsmtmp: bigint;
        let out_stream = new BigUint64Array(16);

        this.S[0] = a_mul(this.S[0]) ^ this.S[13] ^ ainv_mul(this.S[11]);
        fsmtmp = this.r[1] + this.S[13];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[0] = (this.r[0] + this.S[0]) ^ this.r[1] ^ this.S[1];

        this.S[1] = a_mul(this.S[1]) ^ this.S[14] ^ ainv_mul(this.S[12]);
        fsmtmp = this.r[1] + this.S[14];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[1] = (this.r[0] + this.S[1]) ^ this.r[1] ^ this.S[2];

        this.S[2] = a_mul(this.S[2]) ^ this.S[15] ^ ainv_mul(this.S[13]);
        fsmtmp = this.r[1] + this.S[15];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[2] = (this.r[0] + this.S[2]) ^ this.r[1] ^ this.S[3];

        this.S[3] = a_mul(this.S[3]) ^ this.S[0] ^ ainv_mul(this.S[14]);
        fsmtmp = this.r[1] + this.S[0];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[3] = (this.r[0] + this.S[3]) ^ this.r[1] ^ this.S[4];

        this.S[4] = a_mul(this.S[4]) ^ this.S[1] ^ ainv_mul(this.S[15]);
        fsmtmp = this.r[1] + this.S[1];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[4] = (this.r[0] + this.S[4]) ^ this.r[1] ^ this.S[5];

        this.S[5] = a_mul(this.S[5]) ^ this.S[2] ^ ainv_mul(this.S[0]);
        fsmtmp = this.r[1] + this.S[2];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[5] = (this.r[0] + this.S[5]) ^ this.r[1] ^ this.S[6];

        this.S[6] = a_mul(this.S[6]) ^ this.S[3] ^ ainv_mul(this.S[1]);
        fsmtmp = this.r[1] + this.S[3];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[6] = (this.r[0] + this.S[6]) ^ this.r[1] ^ this.S[7];

        this.S[7] = a_mul(this.S[7]) ^ this.S[4] ^ ainv_mul(this.S[2]);
        fsmtmp = this.r[1] + this.S[4];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[7] = (this.r[0] + this.S[7]) ^ this.r[1] ^ this.S[8];

        this.S[8] = a_mul(this.S[8]) ^ this.S[5] ^ ainv_mul(this.S[3]);
        fsmtmp = this.r[1] + this.S[5];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[8] = (this.r[0] + this.S[8]) ^ this.r[1] ^ this.S[9];

        this.S[9] = a_mul(this.S[9]) ^ this.S[6] ^ ainv_mul(this.S[4]);
        fsmtmp = this.r[1] + this.S[6];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[9] = (this.r[0] + this.S[9]) ^ this.r[1] ^ this.S[10];

        this.S[10] = a_mul(this.S[10]) ^ this.S[7] ^ ainv_mul(this.S[5]);
        fsmtmp = this.r[1] + this.S[7];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[10] = (this.r[0] + this.S[10]) ^ this.r[1] ^ this.S[11];

        this.S[11] = a_mul(this.S[11]) ^ this.S[8] ^ ainv_mul(this.S[6]);
        fsmtmp = this.r[1] + this.S[8];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[11] = (this.r[0] + this.S[11]) ^ this.r[1] ^ this.S[12];

        this.S[12] = a_mul(this.S[12]) ^ this.S[9] ^ ainv_mul(this.S[7]);
        fsmtmp = this.r[1] + this.S[9];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[12] = (this.r[0] + this.S[12]) ^ this.r[1] ^ this.S[13];

        this.S[13] = a_mul(this.S[13]) ^ this.S[10] ^ ainv_mul(this.S[8]);
        fsmtmp = this.r[1] + this.S[10];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[13] = (this.r[0] + this.S[13]) ^ this.r[1] ^ this.S[14];

        this.S[14] = a_mul(this.S[14]) ^ this.S[11] ^ ainv_mul(this.S[9]);
        fsmtmp = this.r[1] + this.S[11];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[14] = (this.r[0] + this.S[14]) ^ this.r[1] ^ this.S[15];

        this.S[15] = a_mul(this.S[15]) ^ this.S[12] ^ ainv_mul(this.S[10]);
        fsmtmp = this.r[1] + this.S[12];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out_stream[15] = (this.r[0] + this.S[15]) ^ this.r[1] ^ this.S[0];

        return out_stream;
    }

    /** Generate next keystream and perform encryption */
    next_stream_full_crypt(in_: TArg<BigUint64Array>): TRet<BigUint64Array> {
        let fsmtmp: bigint;
        let out = new BigUint64Array(16);

        this.S[0] = a_mul(this.S[0]) ^ this.S[13] ^ ainv_mul(this.S[11]);
        fsmtmp = this.r[1] + this.S[13];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[0] = in_[0] ^ (this.r[0] + this.S[0]) ^ this.r[1] ^ this.S[1];

        this.S[1] = a_mul(this.S[1]) ^ this.S[14] ^ ainv_mul(this.S[12]);
        fsmtmp = this.r[1] + this.S[14];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[1] = in_[1] ^ (this.r[0] + this.S[1]) ^ this.r[1] ^ this.S[2];

        this.S[2] = a_mul(this.S[2]) ^ this.S[15] ^ ainv_mul(this.S[13]);
        fsmtmp = this.r[1] + this.S[15];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[2] = in_[2] ^ (this.r[0] + this.S[2]) ^ this.r[1] ^ this.S[3];

        this.S[3] = a_mul(this.S[3]) ^ this.S[0] ^ ainv_mul(this.S[14]);
        fsmtmp = this.r[1] + this.S[0];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[3] = in_[3] ^ (this.r[0] + this.S[3]) ^ this.r[1] ^ this.S[4];

        this.S[4] = a_mul(this.S[4]) ^ this.S[1] ^ ainv_mul(this.S[15]);
        fsmtmp = this.r[1] + this.S[1];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[4] = in_[4] ^ (this.r[0] + this.S[4]) ^ this.r[1] ^ this.S[5];

        this.S[5] = a_mul(this.S[5]) ^ this.S[2] ^ ainv_mul(this.S[0]);
        fsmtmp = this.r[1] + this.S[2];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[5] = in_[5] ^(this.r[0] + this.S[5]) ^ this.r[1] ^ this.S[6];

        this.S[6] = a_mul(this.S[6]) ^ this.S[3] ^ ainv_mul(this.S[1]);
        fsmtmp = this.r[1] + this.S[3];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[6] = in_[6] ^(this.r[0] + this.S[6]) ^ this.r[1] ^ this.S[7];

        this.S[7] = a_mul(this.S[7]) ^ this.S[4] ^ ainv_mul(this.S[2]);
        fsmtmp = this.r[1] + this.S[4];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[7] = in_[7] ^(this.r[0] + this.S[7]) ^ this.r[1] ^ this.S[8];

        this.S[8] = a_mul(this.S[8]) ^ this.S[5] ^ ainv_mul(this.S[3]);
        fsmtmp = this.r[1] + this.S[5];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[8] = in_[8] ^(this.r[0] + this.S[8]) ^ this.r[1] ^ this.S[9];

        this.S[9] = a_mul(this.S[9]) ^ this.S[6] ^ ainv_mul(this.S[4]);
        fsmtmp = this.r[1] + this.S[6];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[9] = in_[9] ^(this.r[0] + this.S[9]) ^ this.r[1] ^ this.S[10];

        this.S[10] = a_mul(this.S[10]) ^ this.S[7] ^ ainv_mul(this.S[5]);
        fsmtmp = this.r[1] + this.S[7];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[10] = in_[10] ^(this.r[0] + this.S[10]) ^ this.r[1] ^ this.S[11];

        this.S[11] = a_mul(this.S[11]) ^ this.S[8] ^ ainv_mul(this.S[6]);
        fsmtmp = this.r[1] + this.S[8];
        this.r[1] = T(this.r[0]);
            this.r[0] = fsmtmp;
        out[11] = in_[11] ^ (this.r[0] + this.S[11]) ^ this.r[1] ^ this.S[12];

        this.S[12] = a_mul(this.S[12]) ^ this.S[9] ^ ainv_mul(this.S[7]);
        fsmtmp = this.r[1] + this.S[9];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[12] = in_[12] ^ (this.r[0] + this.S[12]) ^ this.r[1] ^ this.S[13];

        this.S[13] = a_mul(this.S[13]) ^ this.S[10] ^ ainv_mul(this.S[8]);
        fsmtmp = this.r[1] + this.S[10];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[13] = in_[13] ^ (this.r[0] + this.S[13]) ^ this.r[1] ^ this.S[14];

        this.S[14] = a_mul(this.S[14]) ^ this.S[11] ^ ainv_mul(this.S[9]);
        fsmtmp = this.r[1] + this.S[11];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[14] = in_[14] ^ (this.r[0] + this.S[14]) ^ this.r[1] ^ this.S[15];

        this.S[15] = a_mul(this.S[15]) ^ this.S[12] ^ ainv_mul(this.S[10]);
        fsmtmp = this.r[1] + this.S[12];
        this.r[1] = T(this.r[0]);
        this.r[0] = fsmtmp;
        out[15] = in_[15] ^ (this.r[0] + this.S[15]) ^ this.r[1] ^ this.S[0];

        return out;
    }

    /** Perform encryption/decryption */
    crypt(msg: TArg<Uint8Array>): TRet<Uint8Array> {
        const out = new Uint8Array(msg.length);
        let inOffset = 0, outOffset = 0;

        const blockBuffer = new ArrayBuffer(this.blockSize),
            block = new BigUint64Array(blockBuffer),
            block8 = new Uint8Array(blockBuffer);
        while (msg.length - inOffset >= this.blockSize) {
            block8.set(msg.subarray(inOffset, inOffset + this.blockSize));
        
            const encrypted = new Uint8Array(this.next_stream_full_crypt(block).buffer, 0, this.blockSize);
            out.set(encrypted, outOffset);
        
            inOffset += this.blockSize;
            outOffset += this.blockSize;
        }

        if (inOffset < msg.length) {
            const keystream = new Uint8Array(this.next_stream().buffer, 0, this.blockSize);
        
            for (let i = 0; i < msg.length - inOffset; i++)
                out[outOffset + i] = msg[inOffset + i] ^ keystream[i];
        }

        return out;
    }
}