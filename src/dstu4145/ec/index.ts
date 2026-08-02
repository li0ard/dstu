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

    const scalarByteLength = Math.ceil(order.bitLength() / 8),
        pointByteLength = field.LENGTH * 2
    const lengths = Object.freeze({
        fieldByteLength: field.LENGTH,
        pointByteLength,
        scalarByteLength,
        signatureByteLength: scalarByteLength * 2
    });

    // Point operations
    class Point {
        static BASE = new Point(
            toInternal(field.fromHexStringOrBytes(parameters.Gx)),
            toInternal(field.fromHexStringOrBytes(parameters.Gy))
        );
        static ZERO = new Point(new BN(0), new BN(0));
 
        _precomp?: { pos: Point[]; neg: Point[] };
        _double?: Point;
        constructor(public x: BN, public y: BN) {}

        add(p: Point): Point {
            const pz = Point.ZERO.clone();
            const x0 = this.x.clone(), y0 = this.y.clone();
            const x1 = p.x.clone(), y1 = p.y.clone();

            if (this.isZero()) return p;
            if (p.isZero()) return this;

            let lbd: BN, x2: BN;
            if (x0.cmp(x1) !== 0) {
                const tmp = y0.xor(y1), tmp2 = x0.xor(x1);
                lbd = field.mul(tmp, field.invert(tmp2));

                x2 = field.sqr(lbd);
                if (parameters.a === 1) x2 = field.setBit(x2, 0, 1 ^ field.testBit(x2, 0));
                x2 = x2.xor(lbd).xor(x0).xor(x1);
            } else {
                if (y1.cmp(y0) !== 0) return pz;
                if (x1.isZero()) return pz;
                lbd = x1.xor(field.mul(p.y, field.invert(p.x)));
                x2 = field.sqr(lbd);
                if (parameters.a === 1) x2 = field.setBit(x2, 0, 1 ^ field.testBit(x2, 0));
                x2 = x2.xor(lbd);
            }

            const y2 = field.mul(lbd, x1.xor(x2)).xor(x2).xor(y1);
            pz.x = x2;
            pz.y = y2;

            return pz;
        }

        mul(f: BN): Point {
            let pz = Point.ZERO.clone(), p = this.clone();

            for (let j = f.bitLength() - 1; j >= 0; j--) {
                if (f.testn(j)) {
                    pz = pz.add(p);
                    p = p.add(p);
                } else {
                    p = pz.add(p);
                    pz = pz.add(pz);
                }
            }
            return pz;
        }

        negate(): Point { return new Point(this.x, this.x.xor(this.y)); }

        clone(): Point { return new Point(this.x, this.y); }

        isZero(): boolean { return this.x.isZero() && this.y.isZero(); }

        compress(): BN {
            const tmp = field.mul(field.invert(this.x), this.y);

            return field.setBit(toExternal(this.x), 0, field.trace(tmp));
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
            for (let i = 0; i < e; i++) r = r.double();
            return r;
        }

        precomp(width: number): { pos: Point[]; neg: Point[] } {
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

        mulWnaf(f: BN): Point {
            let width = getWindowSize(f.bitLength());
            width = Math.max(2, Math.min(16, width));
 
            const { pos, neg } = this.precomp(width);
            const wnaf = windowNaf(width, f);
 
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

        static expand(xExt: BN): Point {
            const bit = field.testBit(xExt, 0);
            let xCleanExt = xExt.clone();
            xCleanExt = field.setBit(xCleanExt, 0, 0);

            const a = parameters.a ?? 0;
            const traceX = onb ? field.traceOnb(xCleanExt) : field.trace(xCleanExt);
            if ((traceX === 1 && a === 0) || (traceX === 0 && a === 1)) xCleanExt = field.setBit(xCleanExt, 0, 1);

            const xClean = toInternal(xCleanExt);
            const x2 = field.sqr(xClean);
            let rhs = field.mul(x2, xClean);
            if (a === 1) rhs = rhs.xor(x2);
            if (b) rhs = rhs.xor(b);

            let z = field.solve_quad(field.mul(rhs, field.invert(x2)));
            const traceZ = field.trace(z);
            if ((traceZ === 0 && bit === 1) || (traceZ === 1 && bit === 0)) z = field.setBit(z, 0, 1 ^ field.testBit(z, 0));

            return new Point(xClean, field.mul(z, xClean));
        }

        static fromBytes(bytes: TArg<Uint8Array>): Point {
            if(bytes.length == pointByteLength) return new Point(
                toInternal(field.fromHexStringOrBytes(bytes.subarray(0, field.LENGTH))),
                toInternal(field.fromHexStringOrBytes(bytes.subarray(field.LENGTH)))
            );
            else if(bytes.length == field.LENGTH)
                return Point.expand(field.fromHexStringOrBytes(bytes));
            else
                throw new Error(`Invalid bytes length. Must be ${pointByteLength} for uncompressed and ${field.LENGTH} for compressed`);
        }
    }

    const k = order.bitLength() - 1;
    const truncate = (x: BN) => x.maskn(k);

    // Precompute
    Point.BASE.mulWnaf(new BN(3));

    return Object.freeze({
        Field: field, Point,
        ORDER: order,
        parameters, lengths,
        isOnb: !!onb,
        truncate, 
        toInternalField: toInternal,
        toExternalField: toExternal
    });
}