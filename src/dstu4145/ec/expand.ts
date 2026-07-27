import BN from "bn.js";
import type { DSTUShortParameters } from "../const.js";
import { computeMod } from "./index.js";

class Field {
    constructor(public value: BN = new BN(0)) {}

    clone(): Field { return new Field(this.value.clone()); }
    testBit(i: number): 0 | 1 { return this.value.testn(i) ? 1 : 0; }
    setBit(i: number, v: number) { this.value = this.value.setn(i, v == 1); }
    add(v: Field): Field { return new Field(this.value.xor(v.value)); }
    shiftLeft(n: number): Field {
        if (n < 0) throw new Error("Shift amount cannot be negative.");
        return new Field(this.value.ushln(n));
    }

    static get0(): Field { return new Field(new BN(0)); }
    static get1(): Field { return new Field(new BN(1)); }
}

/** Uncompress point without creating full API curve */
export const expandPoint = (
    xBytes: Uint8Array,
    params: DSTUShortParameters
): { x: Uint8Array; y: Uint8Array } => {
    const { m, ks, a } = params;
    const b = new Field(new BN(params.b, 16));

    const modulo = new Field(computeMod(m, ks));
    const fieldByteLength = Math.ceil(m / 8);

    const mod = (f: Field): Field => {
        const cmp = f.value.cmp(modulo.value);
        if (cmp === 0) return Field.get0();
        if (cmp < 0) return f.clone();

        let bag: Field = f;
        const vl = modulo.value.bitLength();
        while (true) {
            bag = bag.add(modulo.shiftLeft(bag.value.bitLength() - vl));
            if (bag.value.bitLength() < vl) return bag;
        }
    }

    const mul = (x: Field, v: Field): Field => {
        let bag = Field.get0();
        let shift: Field = x;
        const vLen = v.value.bitLength();

        for (let i = 0; i < vLen; i++) {
            if (v.testBit(i) == 1) bag = bag.add(shift);
            shift = shift.shiftLeft(1);
        }
        return mod(bag);
    }

    const trace = (x: Field): number => {
        let t: Field = x;
        for (let i = 1; i < m; i++) t = mul(t, t).add(x);
        return t.testBit(0);
    }

    const invert = (f: Field): Field => {
        let r = mod(f), s = modulo;
        let u = Field.get1(), v = Field.get0();

        while (r.value.bitLength() > 1) {
            let j = s.value.bitLength() - r.value.bitLength();
            if (j < 0) {
                [r, s] = [s, r];
                [u, v] = [v, u];
                j = -j;
            }
            s = s.add(r.shiftLeft(j));
            v = v.add(u.shiftLeft(j));
        }
        return u;
    }

    const fsquad = (v: Field): Field => {
        const range_to = Math.floor((m - 1) / 2);
        const val_a = mod(v);

        let val_z = val_a.clone();
        for (let idx = 1; idx <= range_to; idx++) {
            val_z = mul(val_z, val_z);
            val_z = mul(val_z, val_z).add(val_a);
        }

        const val_w = mul(val_z, val_z).add(val_z);
        if (val_w.value.cmp(val_a.value) == 0) return mod(val_z);
        throw new Error("squad eq fail: no square root exists");
    }

    const x = new Field(new BN(xBytes));
    const bit = x.testBit(0);
    const xClean = x.clone();
    xClean.setBit(0, 0);

    const traceX = trace(xClean);
    if ((traceX === 1 && a === 0) || (traceX === 0 && a === 1)) xClean.setBit(0, 1);

    const x2 = mul(xClean, xClean);
    let rhs = mul(x2, xClean);
    if (a === 1) rhs = rhs.add(x2);
    if (b) rhs = rhs.add(b);

    const x2inv = invert(x2);
    const c = mul(rhs, x2inv);
    const z = fsquad(c);

    const traceZ = trace(z);
    if ((traceZ === 0 && bit === 1) || (traceZ === 1 && bit === 0)) {
        const currentBit = z.testBit(0);
        z.setBit(0, 1 ^ currentBit);
    }

    const y = mul(z, xClean);

    return {
        x: new Uint8Array(xClean.value.toArray("be", fieldByteLength)),
        y: new Uint8Array(y.value.toArray("be", fieldByteLength)),
    }
}