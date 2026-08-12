import BN from "bn.js";
import type { DSTUShortParameters } from "../const.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { createField } from "./math.js";

const decompress_matrix = (compress_mulp: BN, mulp: Uint16Array) => {
    const mlen = Math.ceil(compress_mulp.bitLength() / 9);
    if(mlen === 0) return;
    const temp = compress_mulp;
    const mask = new BN(0x1ff);
    for(let j = mlen - 1; j >= 0; j--) {
        mulp[j] = temp.and(mask).toNumber();
        temp.ishrn(9);
    }
}

export const init_onb_parameters = (parameters: DSTUShortParameters) => {
    if(!parameters.onb) throw new Error("Invalid curve: Curve doesn't support ONB");
    const { m, onb, ks } = parameters;

    const mulp = new Uint16Array(2 * m - 1);
    const compress_mulp = new BN(hexToBytes(onb.matrix), "le");
    decompress_matrix(compress_mulp, mulp);
    const root1 = new BN(hexToBytes(onb.root1), "le"),
          root2 = new BN(hexToBytes(onb.root2), "le");

    const multiplyOnb = (x: BN, y: BN): BN => {
        const r = new BN(0);
        const xb = (pos: number) => (x.testn(pos % m) ? 1 : 0);
        const yb = (pos: number) => (y.testn(pos % m) ? 1 : 0);

        for(let j = 0; j < m; j++) {
            let bit = 0;
            for(let i = 0; i < m - 1; i++) {
                const t1 = yb(mulp[2 * i] + j + 1);
                const t2 = yb(mulp[2 * i + 1] + j + 1);
                const t3 = xb(i + j + 1);
                bit ^= (t1 ^ t2) & t3;
            }

            bit ^= yb(mulp[2 * m - 2] + j + 1) & xb(m - 1 + j + 1);
            if(bit) r.setn(j, 1);
        }

        return r;
    }

    const reverseBits = (x: BN): BN => {
        const r = new BN(0);
        for(let i = 0; i < m; i++)
            if (x.testn(i)) r.setn(m - 1 - i, 1);

        return r;
    }

    const toPb: BN[] = new Array(m);
    toPb[0] = root1.clone();
    const { mul } = createField(m, ks);
    for(let i = 1; i < m; i++) toPb[i] = mul(toPb[i - 1], toPb[i - 1]);

    const _toOnb: BN[] = new Array(m);
    _toOnb[0] = new BN(1).shln(m).subn(1);
    for(let i = 1; i < m; i++) _toOnb[i] = multiplyOnb(_toOnb[i - 1], root2);

    const toOnb = _toOnb.map(reverseBits);

    return Object.freeze({
        onbToPb: (x: BN): BN => {
            const r = new BN(0);
            for(let p = 0; p < m; p++)
                if(x.testn(p)) r.ixor(toPb[m - 1 - p]);

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