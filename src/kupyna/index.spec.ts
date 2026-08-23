import { describe, test, expect } from "bun:test";
import { kupyna256, kupyna304, kupyna384, kupyna48, kupyna512 } from ".";
import { hexToBytes, type CHash, type TRet } from "@noble/hashes/utils.js";
import { alphabet } from "../modes/_test_utils.test";

const performTest = (
    hash: CHash<any>,
    input: Uint8Array,
    expected: Uint8Array
) => expect(hash(input)).toStrictEqual(expected as TRet<Uint8Array>);

describe("[CORE] Kupyna-48", () => {
    test("#1", () => performTest(
        kupyna48,
        alphabet.subarray(0,64),
        hexToBytes(`2F6631239875`)
    ));
});

describe("[CORE] Kupyna-256", () => {
    test("#1", () => performTest(
        kupyna256,
        alphabet.subarray(0,64),
        hexToBytes(`08F4EE6F1BE6903B324C4E27990CB24EF69DD58DBE84813EE0A52F6631239875`)
    ));

    test("#2", () => performTest(
        kupyna256,
        alphabet.subarray(0,128),
        hexToBytes("0A9474E645A7D25E255E9E89FFF42EC7EB31349007059284F0B182E452BDA882")
    ));

    test("#3", () => performTest(
        kupyna256,
        alphabet,
        hexToBytes("D305A32B963D149DC765F68594505D4077024F836C1BF03806E1624CE176C08F")
    ));

    test("#4", () => performTest(
        kupyna256,
        alphabet.subarray(255),
        hexToBytes("EA7677CA4526555680441C117982EA14059EA6D0D7124D6ECDB3DEEC49E890F4")
    ));

    test("#5", () => performTest(
        kupyna256,
        alphabet.subarray(0,95),
        hexToBytes("1075C8B0CB910F116BDA5FA1F19C29CF8ECC75CAFF7208BA2994B68FC56E8D16")
    ));

    test("#6", () => performTest(
        kupyna256,
        alphabet.subarray(0,0),
        hexToBytes("CD5101D1CCDF0D1D1F4ADA56E888CD724CA1A0838A3521E7131D4FB78D0F5EB6")
    ));
});

describe("[CORE] Kupyna-304", () => {
    test("#1", () => performTest(
        kupyna304,
        alphabet.subarray(0,128),
        hexToBytes("0A8CADA32B979635657F256B15D5FCA4A174DE029F0B1B4387C878FCC1C00E8705D783FD7FFE")
    ));
});

describe("[CORE] Kupyna-384", () => {
    test("#1", () => performTest(
        kupyna384,
        alphabet.subarray(0,95),
        hexToBytes("D9021692D84E5175735654846BA751E6D0ED0FAC36DFBC0841287DCB0B5584C75016C3DECC2A6E47C50B2F3811E351B8")
    ));
});


describe("[CORE] Kupyna-512", () => {
    test("#1", () => performTest(
        kupyna512,
        alphabet.subarray(0,64),
        hexToBytes("3813E2109118CDFB5A6D5E72F7208DCCC80A2DFB3AFDFB02F46992B5EDBE536B3560DD1D7E29C6F53978AF58B444E37BA685C0DD910533BA5D78EFFFC13DE62A")
    ));

    test("#2", () => performTest(
        kupyna512,
        alphabet.subarray(0,128),
        hexToBytes("76ED1AC28B1D0143013FFA87213B4090B356441263C13E03FA060A8CADA32B979635657F256B15D5FCA4A174DE029F0B1B4387C878FCC1C00E8705D783FD7FFE")
    ));

    test("#3", () => performTest(
        kupyna512,
        alphabet,
        hexToBytes("0DD03D7350C409CB3C29C25893A0724F6B133FA8B9EB90A64D1A8FA93B56556611EB187D715A956B107E3BFC76482298133A9CE8CBC0BD5E1436A5B197284F7E")
    ));

    test("#4", () => performTest(
        kupyna512,
        alphabet.subarray(255),
        hexToBytes("871B18CF754B72740307A97B449ABEB32B64444CC0D5A4D65830AE5456837A72D8458F12C8F06C98C616ABE11897F86263B5CB77C420FB375374BEC52B6D0292")
    ));

    test("#5", () => performTest(
        kupyna512,
        alphabet.subarray(0,192),
        hexToBytes("B189BFE987F682F5F167F0D7FA565330E126B6E592B1C55D44299064EF95B1A57F3C2D0ECF17869D1D199EBBD02E8857FB8ADD67A8C31F56CD82C016CF743121")
    ));

    test("#6", () => performTest(
        kupyna512,
        alphabet.subarray(0,0),
        hexToBytes("656B2F4CD71462388B64A37043EA55DBE445D452AECD46C3298343314EF04019BCFA3F04265A9857F91BE91FCE197096187CEDA78C9C1C021C294A0689198538")
    ));
});

