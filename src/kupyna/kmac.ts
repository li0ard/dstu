import type { Hash, TArg, TRet } from "@noble/hashes/utils.js";
import { uint64sToBytesLE } from "../utils.js";
import { Kupyna256, Kupyna384, Kupyna512 } from "./index.js";
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

    constructor(hash: () => H, kpad: TArg<Uint8Array>, key: TArg<Uint8Array>) {
        this.len = 0n;
        this.h = hash();
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
        let n = this.len;
        let pad_size: bigint;
        if(n < this.threshold) pad_size = this.threshold - 1n - n;
        else pad_size = (BigInt(this.blockLen) - 1n) - ((n - this.threshold) % BigInt(this.blockLen));
        n *= 8n;

        this.h.update(dpad.slice(0, Number(pad_size + 1n)));
        this.h.update(uint64sToBytesLE(new BigUint64Array([n])));
        this.h.update(dpad.slice(16, 20));
        this.h.update(this.ik);
        this.h.digestInto(buffer);
    }

    destroy() {
        throw new Error("Not implemented");
    }
}

/** Kupyna KMAC (256 version) */
export class KupynaKMAC256 extends KupynaKMAC<KupynaKMAC256, Kupyna256> {
    constructor(private key: TArg<Uint8Array>) { super(Kupyna256.create, kpad32, key); }
    _cloneInto(to?: KupynaKMAC256): KupynaKMAC256 {
        to ||= new KupynaKMAC256(this.key);
        to.h = this.h.clone();
        to.len = this.len;
        to.ik = new Uint8Array(this.ik);
        return to;
    }
    clone(): KupynaKMAC256 { return this._cloneInto(); }
}

/** Kupyna KMAC (384 bit version) */
export class KupynaKMAC384 extends KupynaKMAC<KupynaKMAC512, Kupyna384> {
    constructor(private key: TArg<Uint8Array>) { super(Kupyna384.create, kpad48, key); }
    _cloneInto(to?: KupynaKMAC384): KupynaKMAC384 {
        to ||= new KupynaKMAC384(this.key);
        to.h = this.h.clone();
        to.len = this.len;
        to.ik = new Uint8Array(this.ik);
        return to;
    }
    clone(): KupynaKMAC384 { return this._cloneInto(); }
}

/** Kupyna KMAC (512 bit version) */
export class KupynaKMAC512 extends KupynaKMAC<KupynaKMAC512, Kupyna512> {
    constructor(private key: TArg<Uint8Array>) { super(Kupyna512.create, kpad64, key); }
    _cloneInto(to?: KupynaKMAC512): KupynaKMAC512 {
        to ||= new KupynaKMAC512(this.key);
        to.h = this.h.clone();
        to.len = this.len;
        to.ik = new Uint8Array(this.ik);
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