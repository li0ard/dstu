import type { TArg, TRet } from "@noble/hashes/utils.js";
import { ALPHA_MUL, ALPHA_MUL_INV, T as T_ } from "../const.js";
import { bytesToUint64sBE, byte, xorBytes, uint64sToBytesBE } from "../utils.js";

const MAX_UINT64 = (1n << 64n) - 1n;
const not = (w: bigint): bigint => MAX_UINT64 - (w & MAX_UINT64);

const a_mul = (w: bigint): bigint => (w << 8n) ^ ALPHA_MUL[byte(w >> 56n)];
const ainv_mul = (w: bigint): bigint => (w >> 8n) ^ ALPHA_MUL_INV[byte(w)];
const T = (w: bigint): bigint =>
    T_[0][byte(w)] ^
    T_[1][byte(w >> 8n)] ^
    T_[2][byte(w >> 16n)] ^
    T_[3][byte(w >> 24n)] ^
    T_[4][byte(w >> 32n)] ^
    T_[5][byte(w >> 40n)] ^
    T_[6][byte(w >> 48n)] ^
    T_[7][byte(w >> 56n)];

const S_SIZE = 16;

/** Strumok stream cipher */
export class Strumok {
    readonly blockSize = 128;
    readonly keySize: number;
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
        this.S = new BigUint64Array(S_SIZE);
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

        for (let round = 0; round < 2; round++)
            for (let i = 0; i < S_SIZE; i++) this.init(i);
    }

    private updateR(s: number) {
        const r1 = this.r[1];
        this.r[1] = T(this.r[0]);
        this.r[0] = r1 + this.S[s];
    }
    
    private init(i: number) {
        const prev = (i + 15) % S_SIZE;
        const s13 = (i + 13) % S_SIZE;
        const s11 = (i + 11) % S_SIZE;
 
        const outfrom_fsm = (this.r[0] + this.S[prev]) ^ this.r[1];
        this.S[i] = a_mul(this.S[i]) ^ this.S[s13] ^ ainv_mul(this.S[s11]) ^ outfrom_fsm;
        this.updateR(s13);
    }

    private round(i: number): bigint {
        const s13 = (i + 13) % S_SIZE;
        const s11 = (i + 11) % S_SIZE;
 
        this.S[i] = a_mul(this.S[i]) ^ this.S[s13] ^ ainv_mul(this.S[s11]);
        this.updateR(s13);
        const next = (i + 1) % S_SIZE;

        return (this.r[0] + this.S[i]) ^ this.r[1] ^ this.S[next];
    }

    /** Generate next keystream */
    next_stream(): TRet<Uint8Array> {
        const out_stream = new BigUint64Array(S_SIZE);
        for (let i = 0; i < S_SIZE; i++) out_stream[i] = this.round(i);
 
        return uint64sToBytesBE(out_stream);
    }

    /** Perform encryption/decryption */
    crypt(msg: TArg<Uint8Array>): TRet<Uint8Array> {
        const out = new Uint8Array(msg.length);
        let offset = 0;

        while (offset < msg.length) {
            const chunk = xorBytes(msg.subarray(offset), this.next_stream());
            out.set(chunk, offset);
            offset += chunk.length;
        }

        return out;
    }
}