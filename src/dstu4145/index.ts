import { concatBytes, hexToBytes, randomBytes, type TArg, type TRet } from "@noble/hashes/utils.js";
import { DSTU_163_TEST, type DSTUParameters } from "./const.js";
import { binaryWeierstrass } from "./ec/index.js";
import { BN } from "bn.js";

export const dstu4145 = (parameters: DSTUParameters) => {
    const curve = binaryWeierstrass(parameters);
    const n = new BN(curve.ORDER.value);

    const getPublicKey = (secretKey: TArg<Uint8Array>): TRet<Uint8Array> =>
        curve.Point.BASE.mul(curve.Field.fromBytes(secretKey)).negate().toBytes();

    const sign = (
        secretKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        rand?: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
        let e = rand ? new BN(rand).mod(n) : new BN(randomBytes(Math.ceil(curve.parameters.m / 8))).mod(n);
        if (e.isZero()) e = new BN(1);

        const d = new BN(secretKey).mod(n);
        if(d.lten(0) || d.gte(n)) throw new Error("Invalid private key");
        let h = curve.hashToField(digest);
        if(h.is0()) h = curve.Field.get1();
        const Fe = curve.Point.BASE.mul(new curve.Field(e)).x;
        const r = h.mulmod(Fe).value;
        if (r.isZero()) return sign(secretKey, digest, rand);
        const s = e.add(d.mul(r)).mod(n);
        if (s.isZero()) return sign(secretKey, digest, rand);

        return concatBytes(
            new Uint8Array(r.toArray("be", curve.lengths.scalarByteLength)),
            new Uint8Array(s.toArray("be", curve.lengths.scalarByteLength))
        )
    }

    const verify = (
        publicKey: TArg<Uint8Array>,
        digest: TArg<Uint8Array>,
        signature: TArg<Uint8Array>
    ): boolean => {
        if(signature.length != curve.lengths.signatureByteLength) throw new Error("Invalid signature length");
        const Q = curve.Point.fromBytes(publicKey);
        const _r = curve.Field.fromBytes(signature.subarray(0, curve.lengths.scalarByteLength)),
            _s = curve.Field.fromBytes(signature.subarray(curve.lengths.scalarByteLength));

        const h = curve.hashToField(digest);
        const R = curve.Point.BASE.mul(_s).add(Q.mul(_r));
        const y = h.mulmod(R.x);

        return y.value.eq(_r.value);
    }

    /** Decompress point */
    const decompressPoint = (x: TArg<Uint8Array>) => curve.expand(curve.Field.fromBytes(x));

    return Object.freeze({
        getPublicKey,
        sign,
        verify,
        decompressPoint,
        lengths: curve.lengths,
        Point: curve.Point
    });
}

export * from "./const.js";

//const dstu = dstu4145(DSTU_163_TEST);
//console.log(dstu.Point.fromBytes(hexToBytes("057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA")))