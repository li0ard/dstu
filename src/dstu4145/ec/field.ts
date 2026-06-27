import BN from "bn.js";
import type { Curve } from "./curve.js";
import type { TArg, TRet } from "@noble/hashes/utils.js";

export class Field {
    public curve: Curve | null = null;
    public value: BN;

    constructor(value: BN = new BN(0), curve: Curve | null = null) {
        this.value = value;
        this.curve = curve;
    }

    static fromString(str: string, base: number, curve: Curve | null = null): Field {
        return new Field(new BN(str, base), curve);
    }

    static fromInt(v: number, curve: Curve | null = null): Field {
        return new Field(new BN(v), curve);
    }

    static fromU8(v: Uint8Array, curve: Curve | null = null) {
        return new Field(new BN(v, 16), curve)
    }

    public toString(base: number = 10): string {
        return this.value.toString(base);
    }

    public compare(v: Field): number {
        return this.value.cmp(v.value);
    }

    public clone(): Field {
        return Field.fromString(this.toString(16), 16, this.curve);
    }

    public getLength(): number {
        return this.value.bitLength();
    }

    public testBit(i: number): 0 | 1 {
        return this.value.testn(i) ? 1 : 0;
    }

    public setBit(i: number, v: number) {
        this.value = this.value.setn(i, v == 1);
    }

    public shiftLeft(n: number): Field {
        if (n < 0) throw new Error("Shift amount cannot be negative.");
        return new Field(this.value.ushln(n), this.curve);
    }

    public add(v: Field): Field {
        return new Field(this.value.xor(v.value), this.curve || v.curve);
    }

    static hashToField(curve: Curve, hash: TArg<Uint8Array>) {
        return new Field(new BN(hash).maskn(curve.m), curve);
    }

    static get0(curve: Curve | null = null): Field {
        return new Field(new BN(0), curve);
    }

    static get1(curve: Curve | null = null): Field {
        return new Field(new BN(1), curve);
    }

    public is0(): boolean {
        return this.value.isZero();
    }

    public mod(): Field {
        if(!this.curve) throw new Error("Curve not specified");
        const m = this.curve.modulo;
        const cmp = this.compare(m);
        
        if (cmp === 0) return Field.get0();
        if (cmp < 0) return this.clone();
        return this.div(m)[1];
    }

    public mulmod(v: Field): Field {
        return this.mul(v).mod();
    }

    public mul(v: Field): Field {
        let bag = Field.get0();
        let shift = this.clone();
        const vLen = v.getLength();
        
        for (let i = 0; i < vLen; i++) {
            if (v.testBit(i) == 1) bag = bag.add(shift);
            shift = shift.shiftLeft(1);
        }
        bag.curve = this.curve || v.curve;
        return bag;
    }

    public trace(): number {
        if(!this.curve) throw new Error("Curve not specified");
        const m = this.curve.m;
        let t = this.clone();
        for (let i = 1; i < m; i++) t = t.mulmod(t).add(this);
        return t.testBit(0);
    }

    public div(v: Field): [Field, Field] {
        let res = '';
        const c = this.compare(v);
        
        if (c === 0) return [Field.get1(), Field.get0()];
        if (c < 0) return [Field.get0(), this.clone()];
        
        let bag = this.clone();
        const vl = v.getLength();
        
        while (true) {
            const bl = bag.getLength();
            const shift = v.clone().shiftLeft(bl - vl);
            bag = bag.add(shift);
            res += "1";
            
            const blnew = bag.getLength();
            const bdiff = bl - blnew;
            
            if (blnew < vl) {
                res += '0'.repeat(bl - vl);
                return [Field.fromString(res, 2), bag];
            }
            if (bdiff > 1) res += '0'.repeat(bdiff - 1);
        }
    }

    public invert(): Field {
        let r = this.mod();
        let s = this.curve!.modulo;
        let u = Field.get1(this.curve);
        let v = Field.get0(this.curve);
        
        while (r.getLength() > 1) {
            let j = s.getLength() - r.getLength();
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

    public buf8(): TRet<Uint8Array> {
        return new Uint8Array(this.value.toArray());
    }
}