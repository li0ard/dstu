import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { DSTUParameters } from "../const.js";
import BN from "bn.js";

export const binaryWeierstrass = (
    parameters: DSTUParameters
) => {
    class Field {
        constructor(public value: BN = new BN(0)) {}

        compare(v: Field): number { return this.value.cmp(v.value); }

        clone(): Field { return new Field(this.value.clone()); }

        getLength(): number { return this.value.bitLength(); }

        testBit(i: number): 0 | 1 { return this.value.testn(i) ? 1 : 0; }

        setBit(i: number, v: number) { this.value = this.value.setn(i, v == 1); }

        add(v: Field): Field { return new Field(this.value.xor(v.value)); }

        is0(): boolean { return this.value.isZero(); }

        shiftLeft(n: number): Field {
            if (n < 0) throw new Error("Shift amount cannot be negative.");
            return new Field(this.value.ushln(n));
        }

        mod(): Field {
            const cmp = this.compare(modulo);

            if (cmp === 0) return Field.get0();
            if (cmp < 0) return this.clone();
            return this.div(modulo)[1];
        }

        mul(v: Field): Field {
            let bag = Field.get0();
            let shift = this.clone();
            const vLen = v.getLength();

            for (let i = 0; i < vLen; i++) {
                if (v.testBit(i) == 1) bag = bag.add(shift);
                shift = shift.shiftLeft(1);
            }
            return bag;
        }

        trace(): number {
            let t = this.clone();
            for (let i = 1; i < parameters.m; i++) t = t.mulmod(t).add(this);
            return t.testBit(0);
        }

        mulmod(v: Field): Field { return this.mul(v).mod(); }

        div(v: Field): [Field, Field] {
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

        invert(): Field {
            let r = this.mod();
            let s = modulo.clone();
            let u = Field.get1();
            let v = Field.get0();

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

        toBytes(length?: number): TRet<Uint8Array> {
            return new Uint8Array(this.value.toArray("be", length));
        }

        static fromString(str: string, base: number): Field {
            return new Field(new BN(str, base));
        }

        static fromBytes(v: Uint8Array) {
            return new Field(new BN(v, 16));
        }

        static get0(): Field {
            return new Field(new BN(0));
        }

        static get1(): Field {
            return new Field(new BN(1));
        }
    }

    const order = Field.fromString(parameters.order, 16);
    const b = Field.fromString(parameters.b, 16);

    const modulo = Field.get0();
    modulo.setBit(parameters.m, 1);
    modulo.setBit(0, 1);
    for (const i of parameters.ks) modulo.setBit(i, 1);

    const fieldByteLength = Math.ceil(parameters.m / 8),
        scalarByteLength = Math.ceil(order.getLength() / 8),
        pointByteLength = fieldByteLength * 2,
        signatureByteLength = scalarByteLength * 2;

    class Point {
        static BASE = new Point(
            Field.fromString(parameters.Gx, 16),
            Field.fromString(parameters.Gy, 16)
        );
        constructor(public x: Field, public y: Field) {}

        add(p: Point): Point {
            const pz = new Point(Field.get0(), Field.get0());
            const x0 = this.x.clone();
            const y0 = this.y.clone();
            const x1 = p.x.clone();
            const y1 = p.y.clone();

            if (this.iszero()) return p;
            if (p.iszero()) return this;

            let lbd: Field, x2: Field;
            if (x0.compare(x1) !== 0) {
                const tmp = y0.add(y1);
                const tmp2 = x0.add(x1);
                lbd = tmp.mulmod(tmp2.invert(), );

                x2 = lbd.mulmod(lbd);
                if (parameters.a === 1) x2.setBit(0, 1 ^ x2.testBit(0));
                x2 = x2.add(lbd);
                x2 = x2.add(x0);
                x2 = x2.add(x1);
            } else {
                if (y1.compare(y0) !== 0) return pz;
                if (x1.compare(Field.get0()) === 0) return pz;
                lbd = x1.add(p.y.mulmod(p.x.invert()));
                x2 = lbd.mulmod(lbd);
                if (parameters.a === 1) x2.setBit(0, 1 ^ x2.testBit(0));
                x2 = x2.add(lbd);
            }

            let y2 = lbd.mulmod(x1.add(x2));
            y2 = y2.add(x2);
            y2 = y2.add(y1);

            pz.x = x2.clone();
            pz.y = y2.clone();
            return pz;
        }

        mul(f: Field): Point {
            let pz = new Point(Field.get0(), Field.get0());
            let p = this.clone();

            for (let j = f.getLength() - 1; j >= 0; j--) {
                if (f.testBit(j) === 1) {
                    pz = pz.add(p);
                    p = p.add(p);
                } else {
                    p = pz.add(p);
                    pz = pz.add(pz);
                }
            }
            return pz;
        }

        negate(): Point {
            return new Point(this.x, this.x.add(this.y));
        }

        clone(): Point {
            return new Point(this.x, this.y);
        }

        iszero(): boolean {
            return this.x.is0() && this.y.is0();
        }

        compress(): Field {
            const x_inv = this.x.invert();
            const tmp = x_inv.mulmod(this.y);
            const trace = tmp.trace();

            this.x.setBit(0, trace == 1 ? 1 : 0);
            return this.x;
        }

        toBytes(isCompressed = false): TRet<Uint8Array> {
            if(isCompressed) return this.compress().toBytes(fieldByteLength);

            return concatBytes(
                this.x.toBytes(fieldByteLength),
                this.y.toBytes(fieldByteLength),
            );
        }

        static fromBytes(bytes: TArg<Uint8Array>): Point {
            if(bytes.length == pointByteLength) return new Point(
                Field.fromBytes(bytes.subarray(0, fieldByteLength)),
                Field.fromBytes(bytes.subarray(fieldByteLength))
            );
            else if(bytes.length == fieldByteLength)
                return expand(Field.fromBytes(bytes));
            else
                throw new Error(`Invalid bytes length. Must be ${pointByteLength} for uncompressed and ${fieldByteLength} for compressed`);
        }
    }

    const hashToField = (hash: TArg<Uint8Array>) => new Field(new BN(hash).maskn(parameters.m));

    const fsquad = (v: Field): Field => {
        const range_to = Math.floor((parameters.m - 1) / 2);
        const val_a = v.mod();
        
        let val_z = val_a.clone();
        for (let idx = 1; idx <= range_to; idx++) {
            val_z = val_z.mulmod(val_z);
            val_z = val_z.mulmod(val_z);
            val_z = val_z.add(val_a);
        }
        
        const val_w = val_z.mulmod(val_z).add(val_z);
        if (val_w.compare(val_a) == 0) return val_z.mod();
        throw new Error("squad eq fail: no square root exists");
    }

    const expand = (x: Field): Point => {
        const bit = x.testBit(0);
        const xClean = x.clone();
        xClean.setBit(0, 0);
        
        const traceX = xClean.trace();
        const a = parameters.a ?? 0;
        if ((traceX === 1 && a === 0) || (traceX === 0 && a === 1)) xClean.setBit(0, 1);
        
        const x2 = xClean.mulmod(xClean);
        let rhs = x2.mulmod(xClean);
        if (a === 1) rhs = rhs.add(x2);
        if (b) rhs = rhs.add(b);
        
        const x2inv = x2.invert();
        const c = rhs.mulmod(x2inv);
        
        const z = fsquad(c);
 
        const traceZ = z.trace();
        if ((traceZ === 0 && bit === 1) || (traceZ === 1 && bit === 0)) {
            const currentBit = z.testBit(0);
            z.setBit(0, 1 ^ currentBit);
        }
 
        const y = z.mulmod(xClean);
 
        return new Point(xClean, y);
    }

    const lengths = Object.freeze({ fieldByteLength, pointByteLength, scalarByteLength, signatureByteLength });

    return Object.freeze({
        Field, Point,
        ORDER: order, MODULO: modulo,
        parameters, lengths,
        expand, hashToField
    });
}