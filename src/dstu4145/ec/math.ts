import type { TArg, TRet } from "@noble/hashes/utils.js";
import BN from "bn.js";

const SQR_PRECOMP = new Uint16Array([
    0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015,
    0x0040, 0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055,
    0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115,
    0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155,
    0x0400, 0x0401, 0x0404, 0x0405, 0x0410, 0x0411, 0x0414, 0x0415,
    0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455,
    0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515,
    0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554, 0x0555,
    0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015,
    0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055,
    0x1100, 0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115,
    0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155,
    0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415,
    0x1440, 0x1441, 0x1444, 0x1445, 0x1450, 0x1451, 0x1454, 0x1455,
    0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515,
    0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555,
    0x4000, 0x4001, 0x4004, 0x4005, 0x4010, 0x4011, 0x4014, 0x4015,
    0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055,
    0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115,
    0x4140, 0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155,
    0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415,
    0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455,
    0x4500, 0x4501, 0x4504, 0x4505, 0x4510, 0x4511, 0x4514, 0x4515,
    0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555,
    0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015,
    0x5040, 0x5041, 0x5044, 0x5045, 0x5050, 0x5051, 0x5054, 0x5055,
    0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115,
    0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155,
    0x5400, 0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414, 0x5415,
    0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455,
    0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515,
    0x5540, 0x5541, 0x5544, 0x5545, 0x5550, 0x5551, 0x5554, 0x5555
]);

const WORD_BITS = 32;
const MUL_WINDOW = 4, MUL_TABLE_SIZE = 1 << MUL_WINDOW;

const bn2LE = (x: BN, numWords: number): Uint32Array => {
    const arr = new Uint32Array(numWords);
    const bytes = x.toArray("le");
    for(let i = 0; i < bytes.length; i++) arr[i >> 2] |= bytes[i] << ((i & 3) * 8);

    return arr;
}
 
const le2BN = (arr: Uint32Array): BN => {
    const bytes = new Uint8Array(arr.length * 4);
    for(let i = 0; i < arr.length; i++) {
        const w = arr[i];
        bytes[i * 4] = w & 0xff;
        bytes[i * 4 + 1] = (w >>> 8) & 0xff;
        bytes[i * 4 + 2] = (w >>> 16) & 0xff;
        bytes[i * 4 + 3] = (w >>> 24) & 0xff;
    }

    return new BN(bytes, "le");
}

const xorShiftedWordInto = (dst: Uint32Array, val: number, shift: number): void => {
    if(val === 0 || shift < 0) return;
    const wordShift = shift >>> 5, bitShift = shift & 31;
    if(bitShift === 0) {
        if(wordShift < dst.length) dst[wordShift] ^= (val >>> 0);
    } else {
        const lo = (val << bitShift) >>> 0;
        const hi = (val >>> (WORD_BITS - bitShift)) >>> 0;
        if(wordShift < dst.length) dst[wordShift] ^= lo;
        if(wordShift + 1 < dst.length) dst[wordShift + 1] ^= hi;
    }
}

/** Compute curve modulo */
export const computeMod = (m: number, ks: number[]): BN => {
    const modulo = new BN(0);
    modulo.setn(m, 1);
    modulo.setn(0, 1);
    for(const i of ks) modulo.setn(i, 1);

    return modulo;
}

/** Create `GF(2^m)` field */
export const createField = (m: number, ks: number[]) => {
    const modulo = computeMod(m, ks),
        wordsPerElement = Math.ceil(m / WORD_BITS),
        wordsForProduct = 2 * wordsPerElement,
        vl = modulo.bitLength();

    const bMod = (f: BN): BN => {
        // `f` will be mutated
        if(f.bitLength() <= m) return f;

        while(f.bitLength() > m) f.ixor(modulo.ushln(f.bitLength() - vl));
        return f;
    }

    const mod = (f: BN): BN => {
        if(f.bitLength() <= m) return f.clone();

        const words = bn2LE(f, Math.max(wordsForProduct, Math.ceil(f.bitLength() / WORD_BITS) + 1));
        for (let i = words.length - 1; i >= wordsPerElement; i--) {
            const T = words[i];
            if (T === 0) continue;
            words[i] = 0;
            const base = i * WORD_BITS - m;
            xorShiftedWordInto(words, T, base);
            for(const k of ks) xorShiftedWordInto(words, T, base + k);
        }

        return bMod(le2BN(words));
    }

    const mul = (x: BN, v: BN): BN => {
        if(x.eq(v)) return sqr(x);
        const table = new Array<BN>(MUL_TABLE_SIZE);
        table[0] = new BN(0);
        for(let i = 1; i < MUL_TABLE_SIZE; i++) {
            const lowBit = i & (-i);
            const lowBitIdx = Math.log2(lowBit) | 0;
            table[i] = table[i ^ lowBit].xor(x.ushln(lowBitIdx));
        }

        const vb = v.bitLength();
        const acc = new BN(0);
        for(let win = Math.ceil(vb / MUL_WINDOW) - 1; win >= 0; win--) {
            let windowVal = 0;
            for(let b = 0; b < MUL_WINDOW; b++) {
                const bitPos = win * MUL_WINDOW + b;
                if (bitPos < vb && v.testn(bitPos)) windowVal |= (1 << b);
            }
            acc.iushln(MUL_WINDOW).ixor(table[windowVal]);
        }

        return mod(acc);
    }

    const div = (x: BN, v: BN): BN => mul(x, invert(v));

    const sqr = (x: BN): BN => {
        const bytes = x.toArray();
        const out = new Uint8Array(bytes.length * 2);
        for(let i = 0; i < bytes.length; i++) {
            const v = SQR_PRECOMP[bytes[i]];
            out[2 * i] = (v >> 8) & 0xff;
            out[2 * i + 1] = v & 0xff;
        }

        return mod(new BN(out));
    }

    const testBit = (x: BN, i: number): 0 | 1 => x.testn(i) ? 1 : 0;
    const invBit = (x: BN, i: number) => x.setn(i, !x.testn(i));

    const sqrt = (x: BN): BN => {
        let r = mod(x);
        for(let i = 0; i < m - 1; i++) r = sqr(r);
        return r;
    }

    const trace = (x: BN): 0 | 1 => {
        let t = x;
        for(let i = 1; i < m; i++) t = sqr(t).ixor(x);
        return testBit(t, 0);
    }

    const traceOnb = (x: BN): 0 | 1 => {
        let t = 0;
        for(let i = 0; i < m; i++) t ^= testBit(x, i);
        return t as 0 | 1;
    }

    const htrace = (x: BN): BN => {
        let ht = x;
        for(let i = 1; i <= Math.floor((m - 1) / 2); i++) ht = sqr(sqr(ht)).ixor(x);
        return ht;
    }

    const invert = (f: BN): BN => {
        let r = mod(f), s = modulo.clone();
        let u = new BN(1), v = new BN(0);

        while(r.bitLength() > 1) {
            let j = s.bitLength() - r.bitLength();
            if(j < 0) {
                let buf = r;
                r = s;
                s = buf;
                buf = u;
                u = v;
                v = buf;
                j = -j;
            }
            s.ixor(r.ushln(j));
            v.ixor(u.ushln(j));
        }

        return u;
    }

    const solve_quad = (v: BN): BN => {
        const a = mod(v), z = htrace(a);
        if(sqr(z).ixor(z).cmp(a) == 0) return mod(z);

        throw new Error("squad eq fail: no square root exists");
    }

    const hashToField = (hash: TArg<Uint8Array>): BN => {
        const h = new BN(hash);
        return h.imaskn(Math.min(m, h.bitLength()));
    }

    const fromHexStringOrBytes = (v: string | Uint8Array): BN => new BN(v, 16);
    const toBytes = (x: BN, length?: number): TRet<Uint8Array> => new Uint8Array(x.toArray("be", length));

    return Object.freeze({
        MODULO: modulo, LENGTH: Math.ceil(m/8),
        mod, mul, div, sqr, sqrt, invert,
        solve_quad, trace, traceOnb, hashToField, invBit,
        fromHexStringOrBytes, toBytes
    });
}