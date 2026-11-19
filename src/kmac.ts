import { abytes, aexists, ahash, aoutput, clean, type CHash, type Hash, type TArg, type TRet } from "@noble/hashes/utils.js";
import { kupyna256, type _Kupyna256, kupyna384, type _Kupyna384, kupyna512, type _Kupyna512 } from "./kupyna/index.js";

const dpad = /* @__PURE__ */ Uint8Array.from({ length: 128 }, (_, i) => i === 0 ? 0x80 : 0);

const kpad32 = /* @__PURE__ */ new Uint8Array([
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

const kpad48 = /* @__PURE__ */ new Uint8Array([
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

const kpad64 = /* @__PURE__ */ new Uint8Array([
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

abstract class KupynaKMAC<T extends Hash<T>> implements Hash<KupynaKMAC<T>> {
    readonly outputLen: number;
    readonly blockLen: number;
    readonly canXOF = false;
    protected readonly threshold: number;
    protected h: T;
    protected ik: Uint8Array;
    protected len = 0;
    protected finished = false;
    protected destroyed = false;
    private readonly tail = new Uint8Array(12);

    constructor(hash: CHash<T>, kpad: TArg<Uint8Array>, key: TArg<Uint8Array>) {
        ahash(hash);
        abytes(kpad, undefined, "kpad");
        abytes(key, undefined, "key");
        this.h = hash.create();
        this.outputLen = this.h.outputLen;
        this.blockLen = this.h.blockLen;
        if (key.length !== this.h.outputLen) throw new Error("Invalid key length");
        this.h.update(key);
        this.h.update(kpad);
        this.ik = new Uint8Array(key.length);
        for (let i = 0; i < key.length; i++) this.ik[i] = ~key[i] & 0xFF;
        this.threshold = this.blockLen - 12;
    }

    clone(): KupynaKMAC<T> { return this._cloneInto(); }
    _cloneInto(to?: KupynaKMAC<T>): KupynaKMAC<T> {
        const key = new Uint8Array(this.ik.length);
        for (let i = 0; i < key.length; i++) key[i] = ~this.ik[i] & 0xFF;

        to ||= new (this.constructor as any)(key) as KupynaKMAC<T>;
        to.h = this.h.clone();
        to.len = this.len;
        to.ik.set(this.ik);
        to.finished = this.finished;
        to.destroyed = this.destroyed;
        return to;
    }

    update(data: TArg<Uint8Array>): this {
        aexists(this);
        abytes(data, undefined, "data");
        this.len += data.length;
        this.h.update(data);
        return this;
    }

    digest(): TRet<Uint8Array> {
        const buffer = new Uint8Array(this.outputLen);
        this.digestInto(buffer);
        return buffer;
    }

    digestInto(buffer: TArg<Uint8Array>) {
        aexists(this);
        aoutput(buffer, this);
        const { len, blockLen, threshold, tail } = this;

        const zeros = (((threshold - 1 - len) % blockLen) + blockLen) % blockLen;
        this.h.update(dpad.subarray(0, zeros + 1));

        const lo = (len << 3) >>> 0, hi = Math.floor(len / 2 ** 29);
        tail[0] = lo;
        tail[1] = lo >>> 8;
        tail[2] = lo >>> 16;
        tail[3] = lo >>> 24;
        tail[4] = hi;
        tail[5] = hi >>> 8;
        tail[6] = hi >>> 16;
        tail[7] = hi >>> 24;
        this.h.update(tail);

        this.h.update(this.ik);
        this.h.digestInto(buffer);
        this.finished = true;
        this.destroy();
    }

    destroy() {
        this.destroyed = true;
        this.h.destroy();
        clean(this.ik, this.tail);
    }
}

/** Kupyna KMAC (256 version) */
export class KupynaKMAC256 extends KupynaKMAC<_Kupyna256> {
    constructor(key: TArg<Uint8Array>) { super(kupyna256, kpad32, key); }
}

/** Kupyna KMAC (384 bit version) */
export class KupynaKMAC384 extends KupynaKMAC<_Kupyna384> {
    constructor(key: TArg<Uint8Array>) { super(kupyna384, kpad48, key); }
}

/** Kupyna KMAC (512 bit version) */
export class KupynaKMAC512 extends KupynaKMAC<_Kupyna512> {
    constructor(key: TArg<Uint8Array>) { super(kupyna512, kpad64, key); }
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