import { Field } from "./field.js";
import { Point } from "../ec/point.js";
import { randomBytes } from "@noble/hashes/utils.js";
import type { DSTUParameters } from "../const.js";

export class Curve {
    a: number;
    b: Field;
    order: Field;
    base: Point
    m: number;
    ks: number[];

    constructor(params: DSTUParameters) {
        this.a = params.a;
        this.b = Field.fromString(params.b, 16);
        this.order = Field.fromString(params.order, 16);
        this.base = new Point(
            Field.fromString(params.Gx, 16, this),
            Field.fromString(params.Gy, 16, this)
        );

        this.m = params.m;
        this.ks = params.ks;
    }

    get modulo(): Field {
        const m = Field.get0();
        m.setBit(this.m, 1);
        m.setBit(0, 1);
        for(const i of this.ks) m.setBit(i, 1);

        return m;
    }

    random() {
        return this.truncate(Field.fromU8(randomBytes(Math.ceil(this.m / 8))));
    }

    truncate(value: Field) {
        const bitl_o = this.order.getLength();
        let xbit = value.getLength();
        const ret = value.clone();

        while(bitl_o <= xbit) {
            ret.setBit(xbit - 1, 0);
            xbit = ret.getLength();
        }

        return ret.clone();
    }

    private fsquad(v: Field): Field {
        const bitl_m = this.m;
        const range_to = Math.floor((bitl_m - 1) / 2);
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

    expand(x: Field): Point {
        const bit = x.testBit(0);
        const xClean = x.clone();
        xClean.setBit(0, 0);
        
        const traceX = xClean.trace();
        const a = this.a ?? 0;
        if ((traceX === 1 && a === 0) || (traceX === 0 && a === 1)) xClean.setBit(0, 1);
        
        const x2 = xClean.mulmod(xClean);
        let rhs = x2.mulmod(xClean);
        if (a === 1) rhs = rhs.add(x2);
        if (this.b) rhs = rhs.add(this.b);
        
        const x2inv = x2.invert();
        const c = rhs.mulmod(x2inv);
        
        const z = this.fsquad(c);
        const y = z.mulmod(xClean);
        
        const traceY = y.trace();
        if ((traceY === 0 && bit === 1) || (traceY === 1 && bit === 0)) {
            const currentBit = y.testBit(0);
            y.setBit(0, 1 ^ currentBit);
        }
        
        xClean.curve = this;
        y.curve = this;
        
        return new Point(xClean, y);
    }
}