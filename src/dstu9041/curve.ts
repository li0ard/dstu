import type { EdwardsOpts } from "@noble/curves/abstract/edwards.js";
import { Field, mod } from "@noble/curves/abstract/modular.js";
import { bitGet, bitLen, bytesToNumberBE, randomBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { concatBytes } from "@noble/hashes/utils.js";

export const dstu9041Curve = (parameters: EdwardsOpts) => {
    if(parameters.a != 2n) throw new Error("Unsuppored `a` parameter, must be 2");
    if(mod(parameters.p, 8n) != 5n) throw new Error("Unsupported `p` prime");
    const Fp = Field(parameters.p), Fn = Field(parameters.n);
    const { a, d, Gx, Gy } = parameters;

    const isValidXY = (x: bigint, y: bigint): boolean => {
        const x2 = Fp.sqr(x);
        const y2 = Fp.sqr(y);
        const left = Fp.add(x2, Fp.mul(a, y2));
        const right = Fp.add(Fp.ONE, Fp.mul(d, Fp.mul(x2, y2)));

        return Fp.eql(left, right);
    }

    if(!isValidXY(Gx, Gy)) throw new Error("Invalid base point");

    const p_minus_1 = Fp.sub(Fp.ZERO, Fp.ONE);
    const p_minus_1_over_2 = Fp.div(Fp.sub(Fp.ORDER, Fp.ONE), 2n);
    const a_over_d = Fp.div(a, d);

    class Point {
        static BASE = new Point(Gx, Gy, Fp.ONE);
        static ZERO = new Point(Fp.ONE, Fp.ZERO, Fp.ONE);
        static Fp = Fp;
        static Fn = Fn;
        constructor(
            public readonly X: bigint,
            public readonly Y: bigint,
            public readonly Z: bigint
        ) {
            Object.freeze(this);
        }

        get x(): bigint {
            return Fp.div(this.X, this.Z);
        }

        get y(): bigint {
            return Fp.div(this.Y, this.Z);
        }

        add(other: Point): Point {
            const A = Fp.mul(this.Z, other.Z);
            const B = Fp.sqr(A);
            const C = Fp.mul(this.X, other.X);
            const D = Fp.mul(this.Y, other.Y);
            const E = Fp.mul(d, Fp.mul(C, D));
            const F = Fp.sub(B, E);
            const G = Fp.add(B, E);

            const self_sum = Fp.add(this.X, this.Y);
            const other_sum = Fp.add(other.X, other.Y);
            const cross = Fp.mul(self_sum, other_sum);

            const xr = Fp.mul(Fp.mul(A, G), Fp.sub(C, Fp.mul(a, D)));
            const yr = Fp.mul(Fp.mul(A, F), Fp.sub(Fp.sub(cross, C), D));
            const zr = Fp.mul(F, G);

            return new Point(xr, yr, zr);
        }

        multiply(scalar: bigint) {
            if (this.is0()) return Point.ZERO;
            
            let S = new Point(this.X, this.Y, this.Z);
            for (let i = bitLen(scalar) - 2; i >= 0; i--) {
                S = S.add(S);
                if(bitGet(scalar, i) == Fp.ONE) S = S.add(this);
            }

            return S;
        }

        is0(): boolean {
            return Fp.eql(this.x, Fp.ONE) && Fp.eql(this.y, Fp.ZERO);
        }

        assertValidity(): this {
            if(!isValidXY(this.x, this.y)) throw new Error("Assertation failed: point isn't on curve");

            return this;
        }

        toBytes(): TRet<Uint8Array> {
            return concatBytes(Fp.toBytes(this.x), Fp.toBytes(this.y));
        }

        static fromBytes(bytes: TArg<Uint8Array>) {
            if (bytes.length !== 2 * Fp.BYTES) throw new Error(`expected ${2 * Fp.BYTES} bytes, got ${bytes.length}`);
            const x = Fp.fromBytes(bytes.subarray(0, Fp.BYTES));
            const y = Fp.fromBytes(bytes.subarray(Fp.BYTES, 2 * Fp.BYTES));

            return Point.fromAffine(x, y);
        }

        static fromAffine(x: bigint, y: bigint) { return new Point(x, y, Fp.ONE).assertValidity(); }

        static fromX(x: bigint): Point {
            const x2 = Fp.sqr(x);
            if(
                Fp.eql(x, Fp.ZERO) ||
                Fp.eql(x, Fp.ONE) ||
                Fp.eql(x, p_minus_1) ||
                Fp.eql(x2, a_over_d)
            ) throw new Error("Invalid x-coordinate, can't recover y");

            const num = Fp.sub(Fp.ONE, x2);
            const denom = Fp.sub(a, Fp.mul(d, x2));
            const v = Fp.div(num, denom);

            if(Fp.pow(v, p_minus_1_over_2) != Fp.ONE)
                throw new Error("Invalid x-coordinate, non-complience with euler criterion");

            const candidate = Point.fromAffine(x, Fp.sqrt(v));
            if(!candidate.multiply(Fn.ORDER).is0())
                throw new Error("Invalid x-coordinate, can't recover y");

            return candidate;
        }
    }

    const getPublicKey = (secretKey: TArg<Uint8Array>): TRet<Uint8Array> => 
        Point.BASE.multiply(bytesToNumberBE(secretKey)).toBytes();

    const keygen = (): { secretKey: TRet<Uint8Array>, publicKey: TRet<Uint8Array> } => {
        const secretKey = randomBytes(Fp.BYTES);
        const publicKey = getPublicKey(secretKey);

        return { secretKey, publicKey }
    }

    return Object.freeze({ Point, getPublicKey, keygen });
}

export const curve256 = dstu9041Curve({
    p: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE4Dn,
    n: 0x4000000000000000000000000000000029E26087789BC2815BDFF97093543CCFn,
    a: 2n,
    d: 0x18n,
    h: 1n,
    Gx: 0x91F5D0E7E2D417E3108B13B075CDC7756045F8424479FCFE8F23D27250A0883Fn,
    Gy: 0x742F27A268641C9D7DDF69892BE3DF3D8F9CC52260B89A4953C8379C7C0A212Bn
});

export const curve512 = dstu9041Curve({
    p: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC95n,
    n: 0x400000000000000000000000000000000000000000000000000000000000000028A3CE52209E2BD4952882D5574165192C46C0D0311FEA6BF9FECE70EE63B59Fn,
    a: 2n,
    d: 0x10dn,
    h: 1n,
    Gx: 0x5230A1EE747050A072BD7319741586EA520388B6B53094571C821A2FC9A9E83D56665346B5DB04C43E75261DBDA512728FAAFAC48AE9260A5A184E2933E3A400n,
    Gy: 0x53A0D50CC63C9219762F451978AEF214DBCFCC3A5CB5EF27124991A86B42B3A1A832724A0E6B930FDD1DA2E27A540D6B675E4422C444F529C508F0BAE7D0A85n
});