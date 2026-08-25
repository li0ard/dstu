import { concatBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import type { DSTUParameters } from "../const.js";
import BN from "bn.js";
import { bitLength, getWindowSize, windowNaf } from "./wnaf.js";
import { init_onb_parameters } from "./onb.js";
import { createField } from "./math.js";

export const binaryWeierstrass = (parameters: DSTUParameters) => {
    const field = createField(parameters.m, parameters.ks);

    const onb = parameters.onb ? init_onb_parameters(parameters) : undefined;
    const toInternal = (f: BN): BN => onb ? onb.onbToPb(f) : f.clone();
    const toExternal = (f: BN): BN => onb ? onb.pbToOnb(f) : f.clone();

    const order = field.fromHexStringOrBytes(parameters.order);
    const b = toInternal(field.fromHexStringOrBytes(parameters.b));
    const c = field.sqrt(b);

    const isValidXY = (x: BN, y: BN): boolean => {
        const x2 = field.sqr(x);
        const lhs = field.sqr(y).ixor(field.mul(x,y));
        const rhs = field.mul(x2, x).ixor(b);
        // `a` must be 0 or 1, so if a = 1, just add x^2
        if(parameters.a === 1) rhs.ixor(x2);

        return lhs.eq(rhs);
    }

    const scalarByteLength = Math.ceil(order.bitLength() / 8),
        pointByteLength = field.LENGTH * 2
    const lengths = Object.freeze({
        fieldByteLength: field.LENGTH,
        pointByteLength,
        scalarByteLength,
        signatureByteLength: scalarByteLength * 2
    });

    const Madd = (X1: BN, Z1: BN, X2: BN, Z2: BN, x: BN): [BN, BN] => {
        const A = field.mul(X1, Z2);
        const B = field.mul(Z1, X2);
        const T = field.mul(A, B);
        const Znew = field.sqr(A.ixor(B));
        const Xnew = field.mul(Znew, x).ixor(T);

        return [Xnew, Znew];
    }

    const Mdouble = (X: BN, Z: BN): [BN, BN] => {
        const X2 = field.sqr(X);
        const Z2 = field.sqr(Z);
        const T = field.sqr(field.mul(Z2, c));
        const Znew = field.mul(X2, Z2);
        const Xnew = field.sqr(X2).ixor(T);

        return [Xnew, Znew];
    }

    // Point operations
    class Point {
        static BASE = new Point(
            toInternal(field.fromHexStringOrBytes(parameters.Gx)),
            toInternal(field.fromHexStringOrBytes(parameters.Gy))
        );
        static ZERO = new Point(new BN(0), new BN(0));
 
        _precomp?: { pos: Point[]; neg: Point[] };
        _double?: Point;
        constructor(public x: BN, public y: BN) { this.assertValidity(); }

        assertValidity(): this {
            // Skip if point is infinity
            if(!isValidXY(this.x, this.y) && !this.x.isZero() && !this.y.isZero())
                throw new Error("Assertation failed: point isn't on curve");

            return this;
        }

        add(p: Point): Point {
            const pz = Point.ZERO.clone();
            const x0 = this.x.clone(), y0 = this.y.clone();
            const x1 = p.x.clone(), y1 = p.y.clone();

            if(this.isZero()) return p;
            if(p.isZero()) return this;

            let lbd: BN, x2: BN;
            if(x0.cmp(x1) !== 0) {
                lbd = field.div(y0.xor(y1), x0.xor(x1));
                x2 = field.sqr(lbd);
                if(parameters.a === 1) field.invBit(x2, 0); 
                x2.ixor(lbd).ixor(x0).ixor(x1);
            } else {
                if(y1.cmp(y0) !== 0) return pz;
                if(x1.isZero()) return pz;
                lbd = x1.xor(field.div(p.y, p.x));
                x2 = field.sqr(lbd);
                if(parameters.a === 1) field.invBit(x2, 0);
                x2.ixor(lbd);
            }

            const y2 = field.mul(lbd, x1.xor(x2)).ixor(x2).ixor(y1);
            pz.x = x2;
            pz.y = y2;

            return pz;
        }

        mul(f: BN | number): Point {
            if(typeof f == "number") f = new BN(f);
            if(f.isZero() || this.x.isZero()) return Point.ZERO.clone();

            let X1 = this.x.clone(), Z1 = new BN(1);
            const xSqr = field.sqr(this.x);
            let X2 = field.sqr(xSqr).ixor(b), Z2 = xSqr.clone();

            for(let i = f.bitLength() - 2; i >= 0; i--) {
                if(f.testn(i)) {
                    [X1, Z1] = Madd(X1, Z1, X2, Z2, this.x);
                    [X2, Z2] = Mdouble(X2, Z2);
                } else {
                    [X2, Z2] = Madd(X2, Z2, X1, Z1, this.x);
                    [X1, Z1] = Mdouble(X1, Z1);
                }
            }

            // Convert projective coords to affine
            if(Z1.isZero()) return Point.ZERO.clone();
            if(Z2.isZero()) return this.negate();
            const A = field.mul(this.x, Z1).ixor(X1);
            const B = field.mul(this.x, Z2).ixor(X2);
            const C = field.mul(Z1, Z2);
            const D = field.mul(C, this.x);
            const E = field.invert(field.mul(D, Z1));
            const F = field.mul(A, B).ixor(field.mul(C, xSqr.ixor(this.y)));

            const Xk = field.mul(X1, field.mul(D, E));
            const Yk = field.mul(field.mul(A, F), E).ixor(this.y);

            return new Point(Xk, Yk);
        }

        negate(): Point { return new Point(this.x.clone(), this.x.xor(this.y)); }

        clone(): Point { return new Point(this.x.clone(), this.y.clone()); }

        isZero(): boolean { return this.x.isZero() && this.y.isZero(); }

        compress(): BN {
            const tmp = field.div(this.y, this.x);
            return toExternal(this.x).setn(0, field.trace(tmp));
        }

        toBytes(isCompressed = false): TRet<Uint8Array> {
            if(isCompressed) return field.toBytes(this.compress(), field.LENGTH);

            return concatBytes(
                field.toBytes(toExternal(this.x), field.LENGTH),
                field.toBytes(toExternal(this.y), field.LENGTH),
            );
        }

        double(): Point { return this.add(this); }
 
        timesPow2(e: number): Point {
            let r: Point = this;
            for(let i = 0; i < e; i++) r = r.double();
            return r;
        }

        precomp(width: number): { pos: Point[]; neg: Point[] } {
            if(!this._precomp) this._precomp = { pos: [this], neg: [] };

            const pos = this._precomp.pos, neg = this._precomp.neg;
            if(!neg[0]) neg[0] = pos[0].negate();
 
            const len = 1 << Math.max(0, width - 2);
            if(len === 1) return { pos, neg };
 
            const twice = this._double ?? (this._double = this.double());
            for(let i = pos.length; i < len; i++) {
                pos[i] = twice.add(pos[i - 1]);
                neg[i] = pos[i].negate();
            }
 
            return { pos, neg };
        }

        mulWnaf(f: BN): Point {
            let width = getWindowSize(f.bitLength());
            width = Math.max(2, Math.min(16, width));
 
            const { pos, neg } = this.precomp(width);
            const wnaf = windowNaf(width, f);
 
            let R: Point = Point.ZERO;
            let i = wnaf.length;
            if(i > 1) {
                const wi = wnaf[--i];
                const digit = wi >> 16;
                let zeroes = wi & 0xffff;
 
                const n = Math.abs(digit);
                const table = digit < 0 ? neg : pos;
                if((n << 2) < (1 << width)) {
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

            while(i > 0) {
                const wi = wnaf[--i], digit = wi >> 16;
 
                const table = digit < 0 ? neg : pos; 
                R = R.double().add(table[Math.abs(digit) >>> 1]);
                R = R.timesPow2(wi & 0xffff);
            }

            return R;
        }

        /** Deserialize point from bytes (compressed/uncompressed) */
        static fromBytes(bytes: TArg<Uint8Array>): Point {
            // Uncompressed
            if(bytes.length == pointByteLength) return new Point(
                toInternal(field.fromHexStringOrBytes(bytes.subarray(0, field.LENGTH))),
                toInternal(field.fromHexStringOrBytes(bytes.subarray(field.LENGTH)))
            );
            // Compressed (need to recover y-coord)
            else if(bytes.length == field.LENGTH) {
                const xExt = field.fromHexStringOrBytes(bytes);
                const bit = xExt.testn(0);
                xExt.setn(0, 0);

                const traceX = onb ? field.traceOnb(xExt) : field.trace(xExt);
                if((traceX === 1 && parameters.a === 0) || (traceX === 0 && parameters.a === 1))
                    xExt.setn(0, 1);

                const x = toInternal(xExt);
                const x2 = field.sqr(x);
                const rhs = field.mul(x2, x);
                if(parameters.a === 1) rhs.ixor(x2);
                rhs.ixor(b);

                const z = field.solve_quad(field.div(rhs, x2));
                const traceZ = field.trace(z);
                if((traceZ === 0 && bit) || (traceZ === 1 && !bit))
                    field.invBit(z, 0);

                return new Point(x, field.mul(z, x));
            }
            else
                throw new Error(`Invalid bytes length. Must be ${pointByteLength} for uncompressed and ${field.LENGTH} for compressed`);
        }
    }

    // Precompute
    Point.BASE.precomp(4);

    return Object.freeze({
        Field: field, Point,
        ORDER: order,
        MASK: order.bitLength() - 1,
        parameters, lengths,
        isOnb: !!onb,
        toInternalField: toInternal,
        toExternalField: toExternal
    });
}