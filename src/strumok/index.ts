import { abytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { T as T_ } from "../const.js";
import type { StreamCipher } from "../types.js";
import { _U32 } from "../utils.js";
import { gf256Multiply } from "../gf/index.js";

const loadBE = (b: Uint8Array): Uint32Array => {
    const n = b.length >>> 3,
        out = new Uint32Array(n * 2);
    for (let w = 0, p = 0; w < n; w++, p += 8) {
        out[2 * w + 1] = (b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3];
        out[2 * w] = (b[p + 4] << 24) | (b[p + 5] << 16) | (b[p + 6] << 8) | b[p + 7];
    }
    return out;
}

const genAlphaTable = (v: number[]): Uint32Array => {
    const t = new Uint32Array(512);
    for (let c = 0; c < 256; c++) {
        const m0 = gf256Multiply(c, v[0]), m1 = gf256Multiply(c, v[1]),
            m2 = gf256Multiply(c, v[2]), m3 = gf256Multiply(c, v[3]),
            m4 = gf256Multiply(c, v[4]), m5 = gf256Multiply(c, v[5]),
            m6 = gf256Multiply(c, v[6]), m7 = gf256Multiply(c, v[7]);
        t[2 * c + 1] = (m0 << 24) | (m1 << 16) | (m2 << 8) | m3;
        t[2 * c] = (m4 << 24) | (m5 << 16) | (m6 << 8) | m7;
    }

    return t;
}

const AM = /* @__PURE__ */ genAlphaTable([215, 63, 4, 18, 94, 0, 0, 4]),
    AMI = /* @__PURE__ */ genAlphaTable([71, 252, 198, 1, 138, 153, 0, 0]);

const S_SIZE = 16, S_MASK = S_SIZE - 1;

/** Strumok stream cipher */
export class Strumok implements StreamCipher {
    readonly blockSize = 128;
    readonly keySize: number;
    private S: Uint32Array;
    private r: Uint32Array;
    private ks: Uint8Array;

    /**
     * Strumok stream cipher
     * @param key Encryption key (256 or 512 bit)
     */
    constructor(key: TArg<Uint8Array>, iv: TArg<Uint8Array>) {
        abytes(key, undefined, "key");
        abytes(iv, 32, "iv");
        this.keySize = key.length;
        if (this.keySize !== 32 && this.keySize !== 64) throw new Error("Unsupported key length");

        const K = loadBE(key), IV = loadBE(iv);
        const S = this.S = new Uint32Array(S_SIZE * 2);
        this.r = new Uint32Array(4);
        this.ks = new Uint8Array(S_SIZE * 8);

        const put = (i: number, k: number, v = -1, inv = false) => {
            let lo = K[2 * k], hi = K[2 * k + 1];
            if (inv) { lo = ~lo; hi = ~hi; }
            if (v >= 0) { lo ^= IV[2 * v]; hi ^= IV[2 * v + 1]; }
            S[2 * i] = lo;
            S[2 * i + 1] = hi;
        }

        if (this.keySize === 32) {
            put(0, 3, 0); put(1, 2);
            put(2, 1, 1); put(3, 0, 2);
            put(4, 3); put(5, 2, 3);
            put(6, 1, -1, true); put(7, 0, -1, true);
            put(8, 3); put(9, 2);
            put(10, 1, -1, true); put(11, 0);
            put(12, 3); put(13, 2, -1, true);
            put(14, 1); put(15, 0, -1, true);
        } else {
            put(0, 7, 0); put(1, 6);
            put(2, 5); put(3, 4, 1);
            put(4, 3); put(5, 2, 2);
            put(6, 1); put(7, 0, -1, true);
            put(8, 4, 3); put(9, 6, -1, true);
            put(10, 5); put(11, 7, -1, true);
            put(12, 3); put(13, 2);
            put(14, 1, -1, true); put(15, 0);
        }

        for (let round = 0; round < 2; round++)
            for (let i = 0; i < S_SIZE; i++) this.feed(i, true);
    }

    private updateR(j: number) {
        const S = this.S, r = this.r;
        const l = r[0], h = r[1];
        const l2 = r[2], h2 = r[3];

        const b0 = (l & 0xFF) << 1,
            b1 = ((l >>> 8) & 0xFF) << 1,
            b2 = ((l >>> 16) & 0xFF) << 1,
            b3 = (l >>> 24) << 1,
            b4 = (h & 0xFF) << 1,
            b5 = ((h >>> 8) & 0xFF) << 1,
            b6 = ((h >>> 16) & 0xFF) << 1,
            b7 = (h >>> 24) << 1;
        const t0 = T_[0], t1 = T_[1], t2 = T_[2], t3 = T_[3],
            t4 = T_[4], t5 = T_[5], t6 = T_[6], t7 = T_[7];
        r[2] = t0[b0] ^ t1[b1] ^ t2[b2] ^ t3[b3] ^ t4[b4] ^ t5[b5] ^ t6[b6] ^ t7[b7];
        r[3] = t0[b0 | 1] ^ t1[b1 | 1] ^ t2[b2 | 1] ^ t3[b3 | 1] ^
            t4[b4 | 1] ^ t5[b5 | 1] ^ t6[b6 | 1] ^ t7[b7 | 1];

        const lo = l2 + S[j];
        r[1] = h2 + S[j + 1] + (lo > _U32 ? 1 : 0);
        r[0] = lo;
    }

    private feed(i: number, fsm: boolean = false) {
        const S = this.S, r = this.r;
        const j = i << 1,
            j13 = ((i + 13) & S_MASK) << 1,
            j11 = ((i + 11) & S_MASK) << 1;

        const l = S[j], h = S[j + 1], ai = (h >>> 24) << 1;
        let lo = (l << 8) ^ AM[ai],
            hi = ((h << 8) | (l >>> 24)) ^ AM[ai + 1];

        const l11 = S[j11], h11 = S[j11 + 1], bi = (l11 & 0xFF) << 1;
        lo ^= ((l11 >>> 8) | (h11 << 24)) ^ AMI[bi] ^ S[j13];
        hi ^= (h11 >>> 8) ^ AMI[bi + 1] ^ S[j13 + 1];

        if (fsm) {
            const jp = ((i + 15) & S_MASK) << 1,
                fl = r[0] + S[jp],
                fh = r[1] + S[jp + 1] + (fl > _U32 ? 1 : 0);
            lo ^= fl ^ r[2];
            hi ^= fh ^ r[3];
        }

        S[j] = lo;
        S[j + 1] = hi;
        this.updateR(j13);
    }

    private gen(ks: Uint8Array) {
        const S = this.S, r = this.r;
        for (let i = 0; i < S_SIZE; i++) {
            this.feed(i);
            const j = i << 1, jn = ((i + 1) & S_MASK) << 1,
                fl = r[0] + S[j],
                fh = r[1] + S[j + 1] + (fl > _U32 ? 1 : 0),
                ol = fl ^ r[2] ^ S[jn],
                oh = fh ^ r[3] ^ S[jn + 1];

            const p = i << 3;
            ks[p] = oh >>> 24;
            ks[p + 1] = oh >>> 16;
            ks[p + 2] = oh >>> 8;
            ks[p + 3] = oh;
            ks[p + 4] = ol >>> 24;
            ks[p + 5] = ol >>> 16;
            ks[p + 6] = ol >>> 8;
            ks[p + 7] = ol;
        }
    }

    /** Generate next keystream */
    next_stream(): TRet<Uint8Array> {
        const out = new Uint8Array(S_SIZE * 8);
        this.gen(out);
        return out;
    }

    /** Perform encryption/decryption */
    crypt(msg: TArg<Uint8Array>): TRet<Uint8Array> {
        abytes(msg, undefined, "msg");
        const out = new Uint8Array(msg.length);
        for (let offset = 0; offset < msg.length; offset += this.ks.length) {
            this.gen(this.ks);
            const n = Math.min(this.ks.length, msg.length - offset);
            for (let k = 0; k < n; k++) out[offset + k] = msg[offset + k] ^ this.ks[k];
        }

        return out;
    }
}