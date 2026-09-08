import { describe, test, expect } from "bun:test";
import { cbc } from "./cbc";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";
import { alphabet, IV128, IV128_256_rev, IV256, IV256_512, IV512, kalyna128, kalyna128_256_rev, kalyna256, kalyna256_512, kalyna512 } from "./_test_utils.test";
import type { Cipher } from "../types";

const performTest = (
    cipher: Cipher,
    iv: Uint8Array,
    pt: Uint8Array,
    ct: Uint8Array
) => {
    const mode = cbc(cipher, iv);
    expect(mode.encrypt(pt)).toStrictEqual(ct as TRet<Uint8Array>);
    expect(mode.decrypt(ct)).toStrictEqual(pt as TRet<Uint8Array>);
}

describe("[MODE] CBC", () => {
    test("#1", () => performTest(
        kalyna128,
        IV128,
        alphabet.subarray(32, 80),
        hexToBytes("A73625D7BE994E85469A9FAABCEDAAB6DBC5F65DD77BB35E06BD7D1D8EAFC8624D6CB31CE189C82B8979F2936DE9BF14")
    ));

    test("#2", () => performTest(
        kalyna128_256_rev,
        IV128_256_rev,
        hexToBytes("BC8F026FC603ECE05C24FDE87542730999B381870882AC0535D4368C4BABD81B884E96E853EE7E055262D9D204FBE212"),
        alphabet.slice(48, 96).reverse()
    ));

    test("#3", () => performTest(
        kalyna256,
        IV256,
        alphabet.subarray(64, 160),
        hexToBytes("9CDFDAA75929E7C2A5CFC1BF16B42C5AE3886D0258E8C577DC01DAF62D185FB999B9867736B87110F5F1BC7481912C593F48FF79E2AFDFAB9F704A277EC3E557B1B0A9F223DAE6ED5AF591C4F2D6FB22E48334F5E9B96B1A2EA5200F30A406CE")
    ));

    test("#4", () => performTest(
        kalyna256_512,
        IV256_512,
        alphabet.subarray(96,192),
        hexToBytes("B8A2474578C2FEBF3F94703587BD5FDC3F4A4D2F43575B6144A1E1031FB3D1452B7FD52F5E3411461DAC506869FF8D2FAEF4FEE60379AE00B33AA3EAF911645AF8091CD8A45D141D1FB150E5A01C1F26FF3DBD26AC4225EC7577B2CE57A5B0FF")
    ));

    test("#5", () => performTest(
        kalyna512,
        IV512,
        alphabet.subarray(128),
        hexToBytes(
            "D4739B829EF901B24C1162AE4FDEF897EDA41FAC7F5770CDC90E1D1CDF124E8D7831E06B4498A4B6F6EC815DF2461DC9" +
            "9BB0449B0F09FCAA2C84090534BCC9329626FD74EF8F0A0BCB5765184629C3CBF53B0FB134F6D0421174B1C4E884D1CD" +
            "1069A7AD19752DCEBF655842E79B7858BDE01390A760D85E88925BFE38B0FA57"
        )
    ));
});