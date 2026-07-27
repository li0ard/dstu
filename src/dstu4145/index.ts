import { concatBytes, randomBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { 
    DSTU_163, DSTU_163_TEST, DSTU_167,
    DSTU_173, DSTU_173_ONB, DSTU_173_ONB_TEST, DSTU_179, DSTU_179_ONB, DSTU_191,
    DSTU_191_ONB,
    DSTU_233, DSTU_233_ONB, DSTU_257, DSTU_307,
    DSTU_367, DSTU_431,
    DSTU_431_ONB,
    type DSTUParameters
} from "./const.js";
import { binaryWeierstrass } from "./ec/index.js";
import BN from "bn.js";

/** Create DSTU 4145-2002 signer (Big-Endian) */
export const dstu4145 = (parameters: DSTUParameters) => {
    const curve = binaryWeierstrass(parameters);
    const k = curve.ORDER.getLength() - 1;

    const getPublicKey = (secretKey: TArg<Uint8Array>, isCompressed = false): TRet<Uint8Array> =>
        curve.Point.BASE.mul(curve.Field.fromBytes(secretKey)).negate().toBytes(isCompressed);

    const randomPrivateKey = (): TRet<Uint8Array> => new Uint8Array(
        new BN(randomBytes(curve.lengths.scalarByteLength))
        .maskn(k)
        .toArray("be", curve.lengths.scalarByteLength)
    );

    const computePresign = (rand?: TArg<Uint8Array>) => {
        const e = (rand
            ? new BN(rand)
            : new BN(randomBytes(curve.lengths.scalarByteLength))
        ).maskn(k);
        if(rand && e.isZero()) throw new Error("Invalid custom rand for presign (rand = 0)");
        if(e.isZero()) return computePresign(rand);
        const xR = curve.Point.BASE.mul(new curve.Field(e)).x;
        if(xR.is0()) return computePresign(rand);

        return { Fe: xR, e }
    }

    const prepareHash = (digest: TArg<Uint8Array>) => {
        let h = curve.toInternalField(curve.hashToField(digest));
        if (h.is0()) h = curve.Field.get1();
        return h;
    }

    const sign = (
        secretKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        rand?: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        const d = new BN(secretKey).mod(curve.ORDER.value);
        const h = prepareHash(digest);

        const { Fe, e } = computePresign(rand);
        const r = curve.toExternalField(h.mul(Fe)).value.maskn(k);
        if (r.isZero()) return sign(secretKey, digest, rand);
        const s = e.add(d.mul(r)).mod(curve.ORDER.value);
        if (s.isZero()) return sign(secretKey, digest, rand);

        return concatBytes(
            new Uint8Array(s.toArray("be", curve.lengths.scalarByteLength)),
            new Uint8Array(r.toArray("be", curve.lengths.scalarByteLength))
        );
    }

    const verify = (
        publicKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        signature: TArg<Uint8Array>
    ): boolean => {
        if(signature.length != curve.lengths.signatureByteLength) throw new Error("Invalid signature length");
        const Q = curve.Point.fromBytes(publicKey);
        const _s = curve.Field.fromBytes(signature.subarray(0, curve.lengths.scalarByteLength)),
            _r = curve.Field.fromBytes(signature.subarray(curve.lengths.scalarByteLength));
        if (_s.value.isZero() || _s.value.gte(curve.ORDER.value)
            || _r.value.isZero() || _r.value.gte(curve.ORDER.value)
        ) return false;

        const h = prepareHash(digest);
        const R = curve.Point.BASE.mulWnaf(_s).add(Q.mulWnaf(_r));
        const y = curve.toExternalField(h.mul(R.x)).value.maskn(k);

        return y.eq(_r.value);
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
// You need to initialize it manually via `dstu4145`

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