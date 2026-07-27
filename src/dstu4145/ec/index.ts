import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { DSTUParameters } from "../const.js";
import BN from "bn.js";
import { bitLength, getWindowSize, windowNaf } from "./wnaf.js";

export const computeMod = (m: number, ks: number[]): BN => {
    const modulo = new BN(0);
    modulo.setn(m, 1);
    modulo.setn(0, 1);
    for (const i of ks) modulo.setn(i, 1);

    return modulo;
}

export const binaryWeierstrass = (parameters: DSTUParameters) => {
    // GF(2^m) operations
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
            
            let bag: Field = this;
            const vl = modulo.getLength();
            while (true) {
                bag = bag.add(modulo.shiftLeft(bag.getLength() - vl));
                if (bag.getLength() < vl) return bag;
            }
        }

        mul(v: Field): Field {
            let bag = Field.get0();
            let shift: Field = this;
            const vLen = v.getLength();

            for (let i = 0; i < vLen; i++) {
                if (v.testBit(i) == 1) bag = bag.add(shift);
                shift = shift.shiftLeft(1);
            }
            return bag.mod();
        }

        trace(): number {
            let t: Field = this;
            for (let i = 1; i < parameters.m; i++) t = t.mul(t).add(this);
            return t.testBit(0);
        }

        invert(): Field {
            let r = this.mod(), s = modulo;
            let u = Field.get1(), v = Field.get0();

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

        fsquad(): Field {
            const range_to = Math.floor((parameters.m - 1) / 2);
            const val_a = this.mod();

            let val_z = val_a.clone();
            for (let idx = 1; idx <= range_to; idx++) {
                val_z = val_z.mul(val_z);
                val_z = val_z.mul(val_z).add(val_a);
            }

            const val_w = val_z.mul(val_z).add(val_z);
            if (val_w.compare(val_a) == 0) return val_z.mod();
            throw new Error("squad eq fail: no square root exists");
        }

        toBytes(length?: number): TRet<Uint8Array> { return new Uint8Array(this.value.toArray("be", length)); }

        static fromString(str: string): Field { return new Field(new BN(str, 16)); }
        static fromBytes(v: Uint8Array) { return new Field(new BN(v, 16)); }

        static get0(): Field { return new Field(new BN(0)); }
        static get1(): Field { return new Field(new BN(1)); }
    }

    // Convert `n` and `b` to `Field`
    const order = Field.fromString(parameters.order);
    const b = Field.fromString(parameters.b);

    // Compute modulo from `m` and `ks` coefficients
    const modulo = new Field(computeMod(parameters.m, parameters.ks));

    // Compute values length
    const fieldByteLength = Math.ceil(parameters.m / 8),
        scalarByteLength = Math.ceil(order.getLength() / 8),
        pointByteLength = fieldByteLength * 2,
        signatureByteLength = scalarByteLength * 2;
    const lengths = Object.freeze({ fieldByteLength, pointByteLength, scalarByteLength, signatureByteLength });

    // Point operations
    class Point {
        static BASE = new Point(
            Field.fromString(parameters.Gx),
            Field.fromString(parameters.Gy)
        );
        static ZERO = new Point(Field.get0(), Field.get0());
 
        private _precomp?: { pos: Point[]; neg: Point[] };
        private _double?: Point;
        constructor(public x: Field, public y: Field) {}

        add(p: Point): Point {
            const pz = Point.ZERO.clone();
            const x0 = this.x.clone(), y0 = this.y.clone();
            const x1 = p.x.clone(), y1 = p.y.clone();

            if (this.iszero()) return p;
            if (p.iszero()) return this;

            let lbd: Field, x2: Field;
            if (x0.compare(x1) !== 0) {
                const tmp = y0.add(y1), tmp2 = x0.add(x1);
                lbd = tmp.mul(tmp2.invert());

                x2 = lbd.mul(lbd);
                if (parameters.a === 1) x2.setBit(0, 1 ^ x2.testBit(0));
                x2 = x2.add(lbd).add(x0).add(x1);
            } else {
                if (y1.compare(y0) !== 0) return pz;
                if (x1.compare(Field.get0()) === 0) return pz;
                lbd = x1.add(p.y.mul(p.x.invert()));
                x2 = lbd.mul(lbd);
                if (parameters.a === 1) x2.setBit(0, 1 ^ x2.testBit(0));
                x2 = x2.add(lbd);
            }

            const y2 = lbd.mul(x1.add(x2)).add(x2).add(y1);

            pz.x = x2;
            pz.y = y2;
            return pz;
        }

        mul(f: Field): Point {
            let pz = Point.ZERO.clone();
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

        negate(): Point { return new Point(this.x, this.x.add(this.y)); }

        clone(): Point { return new Point(this.x, this.y); }

        iszero(): boolean { return this.x.is0() && this.y.is0(); }

        compress(): Field {
            const x_inv = this.x.invert();
            const tmp = x_inv.mul(this.y);
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

        double(): Point { return this.add(this); }
 
        timesPow2(e: number): Point {
            let r: Point = this;
            for (let i = 0; i < e; i++) r = r.double();
            return r;
        }

        private precomp(width: number): { pos: Point[]; neg: Point[] } {
            if (!this._precomp) this._precomp = { pos: [this], neg: [] };

            const pos = this._precomp.pos, neg = this._precomp.neg;
            if (!neg[0]) neg[0] = pos[0].negate();
 
            const len = 1 << Math.max(0, width - 2);
            if (len === 1) return { pos, neg };
 
            const twice = this._double ?? (this._double = this.double());
            for (let i = pos.length; i < len; i++) {
                pos[i] = twice.add(pos[i - 1]);
                neg[i] = pos[i].negate();
            }
 
            return { pos, neg };
        }

        mulWnaf(f: Field): Point {
            let width = getWindowSize(f.value.bitLength());
            width = Math.max(2, Math.min(16, width));
 
            const { pos, neg } = this.precomp(width);
            const wnaf = windowNaf(width, f.value);
 
            let R: Point = Point.ZERO;
            let i = wnaf.length;
            if (i > 1) {
                const wi = wnaf[--i];
                const digit = wi >> 16;
                let zeroes = wi & 0xffff;
 
                const n = Math.abs(digit);
                const table = digit < 0 ? neg : pos;
 
                if ((n << 2) < (1 << width)) {
                    const highest = bitLength(n);
                    const scale = width - highest;
                    const lowBits = n ^ (1 << (highest - 1));
 
                    const i1 = (1 << (width - 1)) - 1;
                    const i2 = (lowBits << scale) + 1;
                    R = table[i1 >>> 1].add(table[i2 >>> 1]);
 
                    zeroes -= scale;
                }
                else R = table[n >>> 1];

                R = R.timesPow2(zeroes);
            }

            while (i > 0) {
                const wi = wnaf[--i];
                const digit = wi >> 16;
 
                const table = digit < 0 ? neg : pos; 
                R = R.double().add(table[Math.abs(digit) >>> 1]);
                R = R.timesPow2(wi & 0xffff);
            }

            return R;
        }

        static expand(x: Field): Point {
            const bit = x.testBit(0);
            const xClean = x.clone();
            xClean.setBit(0, 0);

            const traceX = xClean.trace();
            const a = parameters.a ?? 0;
            if ((traceX === 1 && a === 0) || (traceX === 0 && a === 1)) xClean.setBit(0, 1);

            const x2 = xClean.mul(xClean);
            let rhs = x2.mul(xClean);
            if (a === 1) rhs = rhs.add(x2);
            if (b) rhs = rhs.add(b);

            const x2inv = x2.invert();
            const c = rhs.mul(x2inv);
            const z = c.fsquad();

            const traceZ = z.trace();
            if ((traceZ === 0 && bit === 1) || (traceZ === 1 && bit === 0)) {
                const currentBit = z.testBit(0);
                z.setBit(0, 1 ^ currentBit);
            }

            return new Point(xClean, z.mul(xClean));
        }

        static fromBytes(bytes: TArg<Uint8Array>): Point {
            if(bytes.length == pointByteLength) return new Point(
                Field.fromBytes(bytes.subarray(0, fieldByteLength)),
                Field.fromBytes(bytes.subarray(fieldByteLength))
            );
            else if(bytes.length == fieldByteLength)
                return Point.expand(Field.fromBytes(bytes));
            else
                throw new Error(`Invalid bytes length. Must be ${pointByteLength} for uncompressed and ${fieldByteLength} for compressed`);
        }
    }

    // Utils
    const hashToField = (hash: TArg<Uint8Array>): Field => {
        const bn = new BN(hash);
        const k = Math.min(parameters.m, bn.bitLength());
        return new Field(bn.maskn(k));
    }

    // precompute
    Point.BASE.mulWnaf(new Field(new BN(3)));

    return Object.freeze({
        Field, Point,
        ORDER: order, MODULO: modulo,
        parameters, lengths,
        hashToField
    });
}