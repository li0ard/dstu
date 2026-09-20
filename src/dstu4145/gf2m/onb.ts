import BN from "bn.js";
import type { DSTUShortParameters } from "../const.js";
import { hexToBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { createField } from "./index.js";

const decompress_matrix = (compress_mulp: BN, mulp: TArg<Uint16Array>) => {
    const mlen = Math.ceil(compress_mulp.bitLength() / 9);
    if(mlen === 0) return;
    const temp = compress_mulp;
    const mask = new BN(0x1ff);
    for(let j = mlen - 1; j >= 0; j--) {
        mulp[j] = temp.and(mask).toNumber();
        temp.ishrn(9);
    }
}

const bnToBits = (x: BN, m: number): TRet<Uint8Array> => {
    const bits = new Uint8Array(m);
    for(let i = 0; i < m; i++) bits[i] = x.testn(i) ? 1 : 0;
    return bits;
}

const bitsToBN = (bits: TArg<Uint8Array>): BN => {
    const r = new BN(0);
    for(let j = 0; j < bits.length; j++) if(bits[j]) r.setn(j, 1);
    return r;
}

export const init_onb_parameters = (parameters: DSTUShortParameters) => {
    if(!parameters.onb) throw new Error("Invalid curve: Curve doesn't support ONB");
    const { m, onb, ks } = parameters;
    const m_sub_1 = m - 1;

    const mulp = new Uint16Array(2 * m - 1);
    const compress_mulp = new BN(hexToBytes(onb.matrix), "le");
    decompress_matrix(compress_mulp, mulp);
    const root1 = new BN(hexToBytes(onb.root1), "le"),
          root2 = new BN(hexToBytes(onb.root2), "le");
    const root2Bits = bnToBits(root2, m);

    const bitAt = (bits: TArg<Uint8Array>, pos: number): number => bits[pos % m];
    const multiplyOnb = (x: BN): BN => {
        const xBits = bnToBits(x, m);
        const out = new Uint8Array(m);

        for(let j = 0; j < m; j++) {
            let bit = 0;
            const j1 = j + 1;
            for(let i = 0; i < m_sub_1; i++) {
                const i2 = i * 2;
                const t1 = bitAt(root2Bits, mulp[i2] + j1),
                    t2 = bitAt(root2Bits, mulp[i2 + 1] + j1),
                    t3 = bitAt(xBits, i + j1);
                bit ^= (t1 ^ t2) & t3;
            }

            bit ^= bitAt(root2Bits, mulp[2 * m - 2] + j1) & bitAt(xBits, m_sub_1 + j1);
            out[j] = bit;
        }

        return bitsToBN(out);
    }

    const reverseBits = (x: BN): BN => {
        const xBits = bnToBits(x, m);
        const out = new Uint8Array(m);
        for(let i = 0; i < m; i++) out[m_sub_1 - i] = xBits[i];
        return bitsToBN(out);
    }

    const toPb: BN[] = new Array(m);
    toPb[0] = root1.clone();
    const { sqr } = createField(m, ks);
    for(let i = 1; i < m; i++) toPb[i] = sqr(toPb[i - 1]);

    const _toOnb: BN[] = new Array(m);
    _toOnb[0] = new BN(1).ishln(m).isubn(1);
    for(let i = 1; i < m; i++) _toOnb[i] = multiplyOnb(_toOnb[i - 1]);

    const toOnb = _toOnb.map(reverseBits);

    return Object.freeze({
        onbToPb: (x: BN): BN => {
            const r = new BN(0);
            for(let p = 0; p < m; p++)
                if(x.testn(p)) r.ixor(toPb[m_sub_1 - p]);

            return r;
        },
        pbToOnb: (x: BN): BN => {
            const r = new BN(0);
            for(let j = 0; j < m; j++)
                if(x.testn(j)) r.ixor(toOnb[j]);

            return r;
        }
    });
}