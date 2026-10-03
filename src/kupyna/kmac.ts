import { abytes, ahash, type CHash, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { uint64sToBytesLE } from "../utils.js";
import { kupyna256, type _Kupyna256, kupyna384, type _Kupyna384, kupyna512, type _Kupyna512 } from "./index.js";
import { numberToBytesLE } from "@noble/curves/utils.js";

const dpad: Readonly<Uint8Array> = numberToBytesLE(128, 128);

const kpad32: Readonly<Uint8Array> = new Uint8Array([
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

const kpad48: Readonly<Uint8Array> = new Uint8Array([
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

const kpad64: Readonly<Uint8Array> = new Uint8Array([
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

abstract class KupynaKMAC<T, H extends Hash<H>> implements Hash<KupynaKMAC<T,H>> {
    readonly outputLen: number;
    readonly blockLen: number;
    readonly canXOF = false;
    protected readonly threshold: bigint;
    protected h: H;
    protected ik: Uint8Array;
    protected len: bigint;

    constructor(hash: CHash<H>, kpad: TArg<Uint8Array>, key: TArg<Uint8Array>) {
        ahash(hash);
        abytes(kpad, undefined, "kpad");
        abytes(key, undefined, "key");
        this.len = 0n;
        this.h = hash.create();
        this.outputLen = this.h.outputLen;
        this.blockLen = this.h.blockLen;
        if(key.length != this.h.outputLen) throw new Error("Invalid key length");
        this.h.update(key);
        this.h.update(kpad);
        this.ik = new Uint8Array(key.length);
        for (let i = 0; i < key.length; i++) this.ik[i] = ~key[i] & 0xFF;
        this.threshold = BigInt(this.blockLen - 12);
    }

    abstract clone(): KupynaKMAC<T,H>;
    abstract _cloneInto(to?: KupynaKMAC<T,H>): KupynaKMAC<T,H>;

    update(data: TArg<Uint8Array>): this {
        abytes(data, undefined, "data");
        this.len += BigInt(data.length);
        this.h.update(data);
        return this;
    }

    digest(): TRet<Uint8Array> {
        const buffer = new Uint8Array(this.outputLen);
        this.digestInto(buffer);

        return buffer;
    }

    digestInto(buffer: TArg<Uint8Array>) {
        if(buffer.length != this.outputLen) throw new Error("digestInto: Invalid buffer length");
        let n = this.len, pad_size: bigint;
        if(n < this.threshold) pad_size = this.threshold - 1n - n;
        else pad_size = (BigInt(this.blockLen) - 1n) - ((n - this.threshold) % BigInt(this.blockLen));
        n *= 8n;

        this.h.update(dpad.subarray(0, Number(pad_size + 1n)));
        this.h.update(uint64sToBytesLE(new BigUint64Array([n])));
        this.h.update(dpad.subarray(16, 20));
        this.h.update(this.ik);
        this.h.digestInto(buffer);
        this.destroy();
    }

    destroy() { this.h.destroy(); }
}

/** Kupyna KMAC (256 version) */
export class KupynaKMAC256 extends KupynaKMAC<KupynaKMAC256, _Kupyna256> {
    constructor(private key: TArg<Uint8Array>) { super(kupyna256, kpad32, key); }
    _cloneInto(to?: KupynaKMAC256): KupynaKMAC256 {
        to ||= new KupynaKMAC256(this.key);
        to.h = this.h.clone();
        to.len = this.len;
        to.ik.set(this.ik);
        return to;
    }
    clone(): KupynaKMAC256 { return this._cloneInto(); }
}

/** Kupyna KMAC (384 bit version) */
export class KupynaKMAC384 extends KupynaKMAC<KupynaKMAC512, _Kupyna384> {
    constructor(private key: TArg<Uint8Array>) { super(kupyna384, kpad48, key); }
    _cloneInto(to?: KupynaKMAC384): KupynaKMAC384 {
        to ||= new KupynaKMAC384(this.key);
        to.h = this.h.clone();
        to.len = this.len;
        to.ik.set(this.ik);
        return to;
    }
    clone(): KupynaKMAC384 { return this._cloneInto(); }
}

/** Kupyna KMAC (512 bit version) */
export class KupynaKMAC512 extends KupynaKMAC<KupynaKMAC512, _Kupyna512> {
    constructor(private key: TArg<Uint8Array>) { super(kupyna512, kpad64, key); }
    _cloneInto(to?: KupynaKMAC512): KupynaKMAC512 {
        to ||= new KupynaKMAC512(this.key);
        to.h = this.h.clone();
        to.len = this.len;
        to.ik.set(this.ik);
        return to;
    }
    clone(): KupynaKMAC512 { return this._cloneInto(); }
}

/** Kupyna KMAC (256 version) */
export const kmac256 = (key: TArg<Uint8Array>, msg: TArg<Uint8Array>): TRet<Uint8Array> =>
    new KupynaKMAC256(key).update(msg).digest();

/** Kupyna KMAC (384 version) */
export const kmac384 = (key: TArg<Uint8Array>, msg: TArg<Uint8Array>): TRet<Uint8Array> =>
    new KupynaKMAC384(key).update(msg).digest();

/** Kupyna KMAC (512 version) */
export const kmac512 = (key: TArg<Uint8Array>, msg: TArg<Uint8Array>): TRet<Uint8Array> =>
    new KupynaKMAC512(key).update(msg).digest();