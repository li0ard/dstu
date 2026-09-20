import type { TArg, TRet } from "@noble/hashes/utils.js";
import BN from "bn.js";

export const SQR_PRECOMP = new Uint16Array([
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

export const WORD_BITS = 32;

const numWordsFor = (x: BN): number => 
    Math.max(1, Math.ceil(Math.max(x.bitLength(), 1) / WORD_BITS));

export const bn2LE = (x: BN, numWords: number = numWordsFor(x)): TRet<Uint32Array> => {
    const arr = new Uint32Array(numWords);
    const bytes = x.toArray("le");
    for(let i = 0; i < bytes.length; i++) arr[i >> 2] |= bytes[i] << ((i & 3) * 8);
    return arr;
}

export const le2BN = (arr: TArg<Uint32Array>): BN => {
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

const wBitLen = (words: TArg<Uint32Array>): number => {
    let nz = words.length - 1;
    while(nz >= 0 && words[nz] === 0) nz--;
    if(nz < 0) return 0;

    let x = words[nz], r = 1, t;
    if((t = x >>> 16) !== 0) { x = t; r += 16; }
    if((t = x >> 8) !== 0) { x = t; r += 8; }
    if((t = x >> 4) !== 0) { x = t; r += 4; }
    if((t = x >> 2) !== 0) { x = t; r += 2; }
    if((t = x >> 1) !== 0) { x = t; r += 1; }

    return r + nz * WORD_BITS;
}

const mul_1x1 = (offset: number, a: number, b: number, dst: TArg<Uint32Array>) => {
    const a1 = a & 0x3fffffff,
        a2 = a1 << 1,
        a4 = a2 << 1,
        tab = [0, a1, a2, a1 ^ a2, a4, a1 ^ a4, a2 ^ a4, a1 ^ a2 ^ a4];

    let s = tab[b & 0x7], l = s;
    s = tab[(b >>> 3) & 0x7];
    l ^= s << 3;
    let h = s >>> 29;
    s = tab[(b >>> 6) & 0x7];
    l ^= s << 6;
    h ^= s >>> 26;
    s = tab[(b >>> 9) & 0x7];
    l ^= s << 9;
    h ^= s >>> 23;
    s = tab[(b >>> 12) & 0x7];
    l ^= s << 12;
    h ^= s >>> 20;
    s = tab[(b >>> 15) & 0x7];
    l ^= s << 15;
    h ^= s >>> 17;
    s = tab[(b >>> 18) & 0x7];
    l ^= s << 18;
    h ^= s >>> 14;
    s = tab[(b >>> 21) & 0x7];
    l ^= s << 21;
    h ^= s >>> 11;
    s = tab[(b >>> 24) & 0x7];
    l ^= s << 24;
    h ^= s >>> 8;
    s = tab[(b >>> 27) & 0x7];
    l ^= s << 27;
    h ^= s >>> 5;
    s = tab[b >>> 30];
    l ^= s << 30;
    h ^= s >>> 2;

    const t2b = a >>> 30;
    if(t2b & 1) {
        l ^= b << 30;
        h ^= b >>> 2;
    }
    if(t2b & 2) {
        l ^= b << 31;
        h ^= b >>> 1;
    }

    dst[offset + 1] = h;
    dst[offset] = l;
}

const mul_2x2 = (
    a1: number, a0: number,
    b1: number, b0: number,
    dst: TArg<Uint32Array>
) => {
    mul_1x1(2, a1, b1, dst);
    mul_1x1(0, a0, b0, dst);
    mul_1x1(4, a0 ^ a1, b0 ^ b1, dst);

    dst[2] ^= dst[5] ^ dst[1] ^ dst[3];
    dst[1] = dst[3] ^ dst[2] ^ dst[0] ^ dst[4] ^ dst[5];
    dst[4] = 0;
    dst[5] = 0;
}

export const mulWords = (a: TArg<Uint32Array>, b: TArg<Uint32Array>): TRet<Uint32Array> => {
    const out = new Uint32Array(a.length + b.length),
        x22 = new Uint32Array(6);

    for(let j = 0; j < b.length; j += 2) {
        const y0 = b[j],
            y1 = j + 1 === b.length ? 0 : b[j + 1];
        if(y0 === 0 && y1 === 0) continue;

        for(let i = 0; i < a.length; i += 2) {
            const x0 = a[i],
                x1 = i + 1 === a.length ? 0 : a[i + 1];
            if(x0 === 0 && x1 === 0) continue;

            mul_2x2(x1, x0, y1, y0, x22);
            out[j + i] ^= x22[0];
            out[j + i + 1] ^= x22[1];
            out[j + i + 2] ^= x22[2];
            out[j + i + 3] ^= x22[3];
        }
    }

    return out;
}

export const sqrWords = (xw: TArg<Uint32Array>): TRet<Uint32Array> => {
    const out = new Uint32Array(xw.length * 2);
    for(let j = 0; j < xw.length; j++) {
        const w = xw[j];
        if(w === 0) continue;

        const b0 = w & 0xff,
            b1 = (w >>> 8) & 0xff,
            b2 = (w >>> 16) & 0xff,
            b3 = (w >>> 24) & 0xff;
        out[2 * j] = SQR_PRECOMP[b0] | (SQR_PRECOMP[b1] << 16);
        out[2 * j + 1] = SQR_PRECOMP[b2] | (SQR_PRECOMP[b3] << 16);
    }
    return out;
}

export const modWords = (a: TArg<Uint32Array>, poly: TArg<Int32Array>): TRet<Uint32Array> => {
    const dN = Math.floor(poly[0] / WORD_BITS),
        len = Math.max(a.length, dN + 1),
        res = new Uint32Array(len);
    res.set(a);

    let j = len - 1;
    while(j > dN) {
        const zz = res[j];
        if(zz === 0) {
            j--;
            continue;
        }
        res[j] = 0;

        for(let k = 1; poly[k]; k++) {
            let n = poly[0] - poly[k];
            const d0 = n % WORD_BITS;
            n = Math.floor(n / WORD_BITS);
            res[j - n] ^= zz >>> d0;
            if(d0) res[j - n - 1] ^= zz << (WORD_BITS - d0);
        }

        const d0m = poly[0] % WORD_BITS;
        res[j - dN] ^= zz >>> d0m;
        if(d0m) res[j - dN - 1] ^= zz << (WORD_BITS - d0m);
    }

    while(j === dN) {
        const d0 = poly[0] % WORD_BITS, zz = res[dN] >>> d0;
        if(zz === 0) break;
        const d1 = WORD_BITS - d0;

        res[dN] = d0 ? (res[dN] << d1) >>> d1 : 0;
        res[0] ^= zz;

        for(let k = 1; poly[k]; k++) {
            const n = Math.floor(poly[k] / WORD_BITS),
                dd0 = poly[k] % WORD_BITS,
                dd1 = WORD_BITS - dd0;
            res[n] ^= zz << dd0;
            const carry = zz >>> dd1;
            if(dd0 && carry) res[n + 1] ^= carry;
        }
    }

    return res;
}

export const invWords = (a: TArg<Uint32Array>, poly: TArg<Uint32Array>): TRet<Uint32Array> => {
    const len = a.length;
    let uu = new Uint32Array(len),
        vv = new Uint32Array(len),
        bb = new Uint32Array(len),
        cc = new Uint32Array(len);

    bb[0] = 1;
    uu.set(a);
    vv.set(poly);

    let ubits = wBitLen(uu), vbits = wBitLen(vv);
    if(ubits === 0) throw new Error("Element is 0, there's no inverse");

    let iter = 100000;
    while(true) {
        if(--iter <= 0) throw new Error("Failed to converge");

        while(ubits && !(uu[0] & 1)) {
            let u0 = uu[0], b0 = bb[0];
            const mask = (b0 & 1) ? 0xffffffff : 0;
            b0 ^= poly[0] & mask;

            let idx = 0;
            for(; idx < len - 1; idx++) {
                const u1 = uu[idx + 1];
                uu[idx] = (u0 >>> 1) | (u1 << 31);
                u0 = u1;

                const b1 = bb[idx + 1] ^ (poly[idx + 1] & mask);
                bb[idx] = (b0 >>> 1) | (b1 << 31);
                b0 = b1;
            }

            uu[idx] = u0 >>> 1;
            bb[idx] = b0 >>> 1;
            ubits--;
        }

        if(ubits <= 32 && uu[0] === 1) break;
        if(ubits < vbits) {
            let t = ubits;
            ubits = vbits;
            vbits = t;
            let tw = uu;
            uu = vv;
            vv = tw;
            tw = bb;
            bb = cc;
            cc = tw;
        }

        for(let idx = 0; idx < len; idx++) {
            uu[idx] ^= vv[idx];
            bb[idx] ^= cc[idx];
        }

        if(ubits === vbits) ubits = wBitLen(uu);
    }

    return bb;
}