import { randomBytes, type TArg } from "@noble/hashes/utils.js";
import type { DSTUParameters, PublicKey, Signature } from "./const.js";
import { Curve, Field, Point } from "./ec/index.js";
import { BN } from "bn.js";

/**
 * Generate public key from private
 * @param parameters Curve parameters
 * @param privateKey Private key
 */
export const getPublicKey = (
    parameters: DSTUParameters,
    privateKey: TArg<Uint8Array>
): PublicKey => {
    const curve = new Curve(parameters);
    const Q = curve.base.mul(Field.fromU8(privateKey, curve)).negate();

    return { x: Q.x.buf8(), y: Q.y.buf8() }
}

/**
 * Generate signature of provided digest
 * @param parameters Curve parameters
 * @param privateKey Private key
 * @param digest Digest to sign
 * @param rand Optional. Predefined random data
 */
export const sign = (
    parameters: DSTUParameters,
    privateKey: TArg<Uint8Array>,
    digest: TArg<Uint8Array>,
    rand?: TArg<Uint8Array>
): Signature => {
    const curve = new Curve(parameters);
    const n = new BN(curve.order.value);
    let e = rand ? new BN(rand).mod(n) : new BN(randomBytes(Math.ceil(curve.m / 8))).mod(n);
    if (e.isZero()) e = new BN(1);

    const d = new BN(privateKey).mod(n);
    if(d.lten(0) || d.gte(curve.order.value)) throw new Error("Invalid private key");
    // h = hash_to_field(H(T))
    let h = Field.hashToField(curve, digest);
    if(h.is0()) h = Field.get1();
    // Fe = eP.x
    const Fe = curve.base.mul(new Field(e)).x;
    // r = h * Fe
    const r = h.mulmod(Fe).value;
    if (r.isZero()) return sign(parameters, privateKey, digest, rand);
    // s = e + dr (mod n)
    const s = e.add(d.mul(r)).mod(n);
    if (s.isZero()) return sign(parameters, privateKey, digest, rand);
        
    return { r: new Uint8Array(r.toArray()), s: new Uint8Array(s.toArray()) }
}

/**
 * Verify signature of provided digest
 * @param parameters Curve parameters
 * @param publicKey Public key
 * @param digest Digest to verify
 * @param signature Signature
 */
export const verify = (
    parameters: DSTUParameters,
    publicKey: PublicKey,
    digest: TArg<Uint8Array>,
    signature: Signature
) => {
    const curve = new Curve(parameters);
    const Q = new Point(
        Field.fromU8(publicKey.x, curve),
        Field.fromU8(publicKey.y, curve),
    );
    const _r = Field.fromU8(signature.r), _s = Field.fromU8(signature.s);

    // h = hash_to_field(H(T))
    const h = Field.hashToField(curve, digest);
    // R = sP + rQ
    const R = curve.base.mul(_s).add(Q.mul(_r));
    // y = h * R.x
    const y = h.mulmod(R.x);

    return y.value.eq(_r.value);
}

/** Decompress point */
export const decompressPoint = (parameters: DSTUParameters, x: TArg<Uint8Array>): Point => {
    const curve = new Curve(parameters);

    return curve.expand(Field.fromU8(x, curve));
}

export * from "./const.js";