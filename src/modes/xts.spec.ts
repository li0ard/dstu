import { describe, test, expect } from "bun:test";
import { xts } from "./xts";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { alphabet, IV128, IV128_256, IV256, IV256_512, IV512, kalyna128, kalyna128_256, kalyna256, kalyna256_512, kalyna512 } from "./_test_utils.test";
import type { Cipher } from "../types";

const performTest = (
    cipher: Cipher,
    iv: Uint8Array,
    pt: Uint8Array,
    ct: Uint8Array,
) => {
    const mode = xts(cipher);
    expect(mode.encrypt(pt, iv)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.decrypt(ct, iv)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("[MODE] XTS", () => {
    test("#1", () => performTest(
        kalyna128,
        IV128,
        alphabet.subarray(32, 64),
        hexToBytes("B3E431B3FBAF31108C302669EE7116D1CF518B6D329D30618DF5628E426BDEF1")
    ));

    test("#1 (pad)", () => performTest(
        kalyna128,
        IV128,
        alphabet.subarray(32, 62),
        hexToBytes("48F3055ED2832222085005209C9D4D41B3E431B3FBAF31108C302669EE71")
    ));

    test("#2", () => performTest(
        kalyna128_256,
        IV128_256,
        alphabet.subarray(48, 80),
        hexToBytes("830AC78A6F629CB4C7D5D156FD84955BD0998CA1E0BC1FF135676BF2A2598FA1")
    ));

    test("#2 (pad)", () => performTest(
        kalyna128_256,
        IV128_256,
        alphabet.subarray(48, 89),
        hexToBytes("830AC78A6F629CB4C7D5D156FD84955B470EEFDDEE38B59F0D836B65635B0A63D0998CA1E0BC1FF135")
    ));

    test("#3", () => performTest(
        kalyna256,
        IV256,
        alphabet.subarray(64, 160),
        hexToBytes(
            "E0E51EAEA6A3134600758EA7F87E88025D8B82897C8DB099B843054C3A51883756913571530BA8FA23003E337627E698" +
            "674B807E847EC6B2292627736562F9F62B2DE9E6AAC5DF74C09A0C5CF80280174AEC9BDD4E73F7D63EDBC29A6922637A"
        )
    ));

    test("#3 (pad)", () => performTest(
        kalyna256,
        IV256,
        alphabet.subarray(64, 129),
        hexToBytes(
            "E0E51EAEA6A3134600758EA7F87E88025D8B82897C8DB099B843054C3A5188374F5254E38066B77FA14FEE3292464B60" +
            "7E8AF1398B2A91C4480B698D64D13AE856"
        )
    ));

    test("#4", () => performTest(
        kalyna256_512,
        IV256_512,
        alphabet.subarray(96, 192),
        hexToBytes(
            "30663E4686574B343A1898E46973CD37DB9D775D356512EB59E723397F2A333CE2C0E96538781FF48EA1D93BDF88FFF8" +
            "BB7BC4FB80A609881220C7FE21881C7374F65B232A8F94CD0E3DDC7614830C23CFCE98ADC5113496F9E106E8C8BFF3AB"
        )
    ));

    test("#4 (pad)", () => performTest(
        kalyna256_512,
        IV256_512,
        alphabet.subarray(96, 161),
        hexToBytes(
            "30663E4686574B343A1898E46973CD37DB9D775D356512EB59E723397F2A333C6DE04CB3235A2DA92493537248DE4368" +
            "879A7CC4166B25C9BFD1AD8EAEA3484BE2"
        )
    ));

    test("#5", () => performTest(
        kalyna512,
        IV512,
        alphabet.subarray(128),
        hexToBytes(
            "5C6250BD2E40AAE27E1E57512CD38E6A51D0C2B04F0D6A50E0CB43358B8C4E8BA361331436C6FFD38D77BBBBF5FEC56A" +
            "234108A6CC8CB298360943E849E5BD64D26ECA2FA8AEAD070656C3777BA412BCAF3D2F08C26CF86CA8F0921043A15D70" +
            "9AE1112611E22D4396E582CCB661E0F778B6F38561BC338AFD5D1036ED8B322D"
        )
    ));

    test("#5 (pad)", () => performTest(
        kalyna512,
        IV512,
        alphabet.subarray(128, 225),
        hexToBytes(
            "C2822787D3CB2D13168B126583CF28E3B194F153088CF46BD745B22D1776BCB035C6CB17D8C1FBD127954C2A5D5F5AFB" +
            "ECF976E34966AB85142192A2463A541F5C6250BD2E40AAE27E1E57512CD38E6A51D0C2B04F0D6A50E0CB43358B8C4E8B" +
            "A3"
        )
    ));
});