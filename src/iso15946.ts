import type { CHash, Hash, TArg, TRet } from "@noble/hashes/utils.js";
import { AsnConvert, AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { Gost3431195 } from "./dstu9311/hash.js";

const KEY_LENGTH = new Uint8Array([0,0,1,0]);
const COUNTER = new Uint8Array([0,0,0,1]);

class SharedInfo {
    @AsnProp({ type: AlgorithmIdentifier })
    keyInfo = new AlgorithmIdentifier();

    @AsnProp({ type: AsnPropTypes.OctetString, context: 0, optional: true })
    entityInfo?: ArrayBuffer;

    @AsnProp({ type: AsnPropTypes.OctetString, context: 2 })
    suppPubInfo = new ArrayBuffer(0);

    constructor(params: Partial<SharedInfo> = {}) {
        Object.assign(this, params);
    }
}

const removeLeadZeros = (bytes: TArg<Uint8Array>): TRet<Uint8Array> => {
    const idx = bytes.findIndex(i => i !== 0);
    return idx === -1 ? new Uint8Array() : bytes.slice(idx);
}

const encodeSharedInfo = (oid: string, ukm?: TArg<Uint8Array>) => new Uint8Array(AsnConvert.serialize(
    new SharedInfo({
        keyInfo: new AlgorithmIdentifier({
            algorithm: oid,
            parameters: null
        }),
        entityInfo: ukm as ArrayBuffer | undefined,
        suppPubInfo: KEY_LENGTH.buffer
    })
));

/** ISO/IEC 15946 KDF function */
export const iso15946_kdf = (
    hash: CHash<Hash<any>>,
    wrapAlgoOid: string,
    inputData: TArg<Uint8Array>,
    ukm?: TArg<Uint8Array>
): TRet<Uint8Array> => {
    if(hash.outputLen != 32)
        throw new Error("Invalid hash function. Output length must be 32 bytes");

    const hasher = hash.create();
    return hasher.update(hasher instanceof Gost3431195
        ? removeLeadZeros(inputData)
        : inputData
    ).update(COUNTER).update(encodeSharedInfo(wrapAlgoOid, ukm)).digest();
}