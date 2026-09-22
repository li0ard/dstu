// Test vectors calculated from UAPKI:
// URL: https://github.com/specinfo-ua/UAPKI/blob/main/library/test/data/decrypt.json
// Private key taken from `test-diia.p12` file
// UKM, IV, wcek, ciphertext taken from `EnvelopedData` payload
import { describe, test, expect } from "bun:test";
import { dstu4145EncrypterWithGost, dstu431, type EncryptedMessage } from ".";
import type { ECDSA } from "../types";
import { hexToBytes } from "@noble/hashes/utils.js";

const MESSAGE = new TextEncoder().encode("The quick brown fox jumps over the lazy dog");
const secretKey = hexToBytes("4D9E8018B2E94D0D69752CADD7A414513405CE8D094E035E88E17C872FE20BAE5AD8A12364C9E42E23F065B01BF0CAAB0FD5A41B1D18").reverse();

const performTest = (
    signer: ECDSA,
    privateKey: Uint8Array,
    publicKey: Uint8Array,
    message: EncryptedMessage
) => expect(dstu4145EncrypterWithGost(signer).decrypt(privateKey, publicKey, message)).toStrictEqual(MESSAGE);

describe("[ECIES] DSTU 4145-2002 (PB)", () => {
    test("#1", () => performTest(
        dstu431,
        secretKey,
        hexToBytes("7214A3192660A544555CBC67A15C4E0E28C81C2FF3DDE4D9E210A20C6B54807FED94BF234A9F78C8294F8D30AB63A9AF0D1B17311618").reverse(),
        {
            iv: hexToBytes("7A64CB28292630D8"),
            wcek: hexToBytes("71AC0FC0333D6E07F242626738DE7A14B3C30111B4F8EE15AC729301DD010FC8D1FCAE9403E7B1C0EDFBA111"),
            data: hexToBytes("E1E2EB634A41BE15EE525C76BD836B1ACE51BE5ADD2041803365EFEFC7EA84051FCC854A04F5C4F7006858")
        }
    ));

    test("#2", () => performTest(
        dstu431,
        secretKey,
        hexToBytes("B239466810DB061A3AAA34606DB3F1EA48C76FB2375DBBEEBDD94A5B85A985BF6CC83E399BD19BBDF76844B34BE968FCC20146FD3C6C").reverse(),
        {
            ukm: hexToBytes("E6DAB6A634D65C1CD9C1BBD87B0603F14ED95692A4AB91CB7AB498D35F0EFDA553719045E60CC56F5341A5DE23EDBD2CB0875C68845DD69F06CB3B0021419D8D"),
            iv: hexToBytes("C84E0171258F73D6"),
            wcek: hexToBytes("552C59DDE116121A38BDA35F9C61B8AEDCF1DB6B02D56FF32CAD339B15EB905D6754DC9FAD1C5E778792E69D"),
            data: hexToBytes("D6AF4BA7519FA32806A20CAC62BC9D4A7F5BA60E324E7FF56184179F111FFFB8ABE6233413D4DB2EE533FE")
        }
    ));
});