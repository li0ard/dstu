import { concatBytes, randomBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { 
    DSTU_163, DSTU_167, DSTU_173, DSTU_179, DSTU_191,
    DSTU_233, DSTU_257, DSTU_307, DSTU_367, DSTU_431,
    type DSTUParameters
} from "./const.js";
import { binaryWeierstrass } from "./ec/index.js";
import BN from "bn.js";

/** Create DSTU 4145-2002 signer (Big-Endian) */
export const dstu4145 = (parameters: DSTUParameters) => {
    const curve = binaryWeierstrass(parameters);
    const { Field, Point, truncate } = curve;

    const getPublicKey = (secretKey: TArg<Uint8Array>, isCompressed = false): TRet<Uint8Array> =>
        Point.BASE.mul(Field.fromHexStringOrBytes(secretKey)).negate().toBytes(isCompressed);

    const randomPrivateKey = (): TRet<Uint8Array> => Field.toBytes(
        truncate(new BN(randomBytes(curve.lengths.scalarByteLength))),
        curve.lengths.scalarByteLength
    )

    const computePresign = (rand?: TArg<Uint8Array>) => {
        const e = truncate(rand
            ? new BN(rand)
            : new BN(randomBytes(curve.lengths.scalarByteLength))
        );
        if(rand && e.isZero()) throw new Error("Invalid custom rand for presign (rand = 0)");
        if(e.isZero()) return computePresign(rand);
        const xR = Point.BASE.mul(e).x;
        if(xR.isZero()) return computePresign(rand);

        return { Fe: xR, e }
    }

    const prepareHash = (digest: TArg<Uint8Array>) => {
        let h = curve.toInternalField(curve.Field.hashToField(digest));
        if (h.isZero()) h = new BN(1);
        return h;
    }

    const sign = (
        secretKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        rand?: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        const d = new BN(secretKey).mod(curve.ORDER);
        const h = prepareHash(digest);

        const { Fe, e } = computePresign(rand);
        const r = truncate(curve.toExternalField(Field.mul(h, Fe)))
        if (r.isZero()) return sign(secretKey, digest, rand);
        const s = e.add(d.mul(r)).mod(curve.ORDER); // BN
        if (s.isZero()) return sign(secretKey, digest, rand);

        return concatBytes(
            Field.toBytes(s, curve.lengths.scalarByteLength),
            Field.toBytes(r, curve.lengths.scalarByteLength),
        );
    }

    const verify = (
        publicKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        signature: TArg<Uint8Array>
    ): boolean => {
        if(signature.length != curve.lengths.signatureByteLength) throw new Error("Invalid signature length");
        const Q = Point.fromBytes(publicKey);
        const _s = curve.Field.fromHexStringOrBytes(signature.subarray(0, curve.lengths.scalarByteLength)),
            _r = curve.Field.fromHexStringOrBytes(signature.subarray(curve.lengths.scalarByteLength));
        if (_s.isZero() || _s.gte(curve.ORDER) || _r.isZero() || _r.gte(curve.ORDER))
            return false;

        const h = prepareHash(digest); // Field
        const R = Point.BASE.mulWnaf(_s).add(Q.mulWnaf(_r));
        const y = truncate(curve.toExternalField(Field.mul(h, R.x)));

        return y.eq(_r);
    }

    const keygen = (isCompressed = false): { secretKey: TRet<Uint8Array>, publicKey: TRet<Uint8Array> } => {
        const secretKey = randomPrivateKey();
        const publicKey = getPublicKey(secretKey, isCompressed);

        return { secretKey, publicKey }
    }

    return Object.freeze({
        getPublicKey,
        sign,
        verify,
        keygen,
        lengths: curve.lengths
    });
}

export * from "./const.js";
export * from "./ec/expand.js";

// ONB curves don't preinitialized because `multiplyOnb` is slow O(m^3) function
// You need to initialize them manually via `dstu4145`

/** DSTU 4145-2002 163 bit curve */
export const dstu163 = dstu4145(DSTU_163);
/** DSTU 4145-2002 167 bit curve */
export const dstu167 = dstu4145(DSTU_167);
/** DSTU 4145-2002 173 bit curve */
export const dstu173 = dstu4145(DSTU_173);
/** DSTU 4145-2002 179 bit curve */
export const dstu179 = dstu4145(DSTU_179);
/** DSTU 4145-2002 191 bit curve */
export const dstu191 = dstu4145(DSTU_191);
/** DSTU 4145-2002 233 bit curve */
export const dstu233 = dstu4145(DSTU_233);
/** DSTU 4145-2002 257 bit curve */
export const dstu257 = dstu4145(DSTU_257);
/** DSTU 4145-2002 307 bit curve */
export const dstu307 = dstu4145(DSTU_307);
/** DSTU 4145-2002 367 bit curve */
export const dstu367 = dstu4145(DSTU_367);
/** DSTU 4145-2002 431 bit curve */
export const dstu431 = dstu4145(DSTU_431);