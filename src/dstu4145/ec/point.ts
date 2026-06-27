import { Field } from "./field.js";

export class Point {
    public x: Field;
    public y: Field;

    constructor(x: Field, y: Field) {
        this.x = x;
        this.y = y;
    }

    public add(p: Point): Point {
        const curve = this.x.curve;
        const a = Field.fromInt(curve?.a ?? 0, curve);
        const pz = new Point(Field.get0(curve), Field.get0(curve));

        const x0 = this.x.clone();
        const y0 = this.y.clone();
        const x1 = p.x.clone();
        const y1 = p.y.clone();

        if (this.iszero()) return p;
        if (p.iszero()) return this;

        let lbd: Field;
        let x2: Field;

        if (x0.compare(x1) !== 0) {
            const tmp = y0.add(y1);
            const tmp2 = x0.add(x1);
            lbd = tmp.mulmod(tmp2.invert());

            x2 = a.add(lbd.mulmod(lbd));
            x2 = x2.add(lbd);
            x2 = x2.add(x0);
            x2 = x2.add(x1);
        } else {
            if (y1.compare(y0) !== 0) return pz;
            if (x1.compare(Field.get0()) === 0) return pz;
            lbd = x1.add(p.y.mulmod(p.x.invert()));
            x2 = lbd.mulmod(lbd).add(a);
            x2 = x2.add(lbd);
        }

        let y2 = lbd.mulmod(x1.add(x2));
        y2 = y2.add(x2);
        y2 = y2.add(y1);

        pz.x = x2.clone();
        pz.y = y2.clone();
        return pz;
    }


    public mul(f: Field): Point {
        let pz = new Point(Field.get0(f.curve), Field.get0(f.curve));
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

    public negate(): Point {
        return new Point(this.x, this.x.add(this.y));
    }

    public clone(): Point {
        return new Point(this.x, this.y);
    }

    public iszero(): boolean {
        return this.x.is0() && this.y.is0();
    }

    public compress(): Field {
        const x_inv = this.x.invert();
        const tmp = x_inv.mulmod(this.y);
        const trace = tmp.trace();

        this.x.setBit(0, trace == 1 ? 1 : 0)
        return this.x;
    }
}