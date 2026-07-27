import { describe, test, expect } from "bun:test";
import { dstu257, dstu4145, dstu431, DSTU_163_TEST, DSTU_173_ONB_TEST } from ".";
import { hexToBytes, type TRet } from "@noble/hashes/utils.js";

const performTest = (
    signer: any,
    privateKey: Uint8Array,
    digest: Uint8Array,
    rand: Uint8Array,
    expectedPk: Uint8Array,
    expectedSign: Uint8Array
) => {
    const publicKey = signer.getPublicKey(privateKey);
    const signature = signer.sign(privateKey, digest, rand);

    expect(publicKey).toStrictEqual(expectedPk as TRet<Uint8Array>);
    expect(signature).toStrictEqual(expectedSign as TRet<Uint8Array>);
    expect(signer.verify(publicKey, digest, signature)).toBeTrue();
    expect(signer.verify(publicKey, digest, signer.sign(privateKey, digest))).toBeTrue();
}


describe("[CORE] DSTU 4145-2002 (PB)", () => {
    const digest = hexToBytes("09C9C44277910C9AAEE486883A2EB95B7180166DDF73532EEB76EDAEF52247FF");

    test("#1 (m=163)", () => {
        const dstu163_test = dstu4145(DSTU_163_TEST);
        const privateKey = hexToBytes("0183F60FDF7951FF47D67193F8D073790C1C9B5A3E");
        const rand = hexToBytes("01025E40BD97DB012B7A1D79DE8E12932D247F61C6");
        const expectedPk = hexToBytes("057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA03E85444324BCF06AD85ABF6AD7B5F34770532B9AA");
        const expectedSign = hexToBytes("02100D86957331832B8E8C230F5BD6A332B3615ACA0274EA2C0CAA014A0D80A424F59ADE7A93068D08A7");

        performTest(dstu163_test, privateKey, digest, rand, expectedPk, expectedSign);
    }, 10000);

    test("#2 (m=257)", () => {
        const privateKey = hexToBytes("77FD46E42B36B76F551426CAFCECDD2F8F4E0DF00EA62886E4343D59DA35FB0FBF");
        const rand = hexToBytes("29A585739F458AE951D39292F2171D7658AEB636D4A9A2F9AA6C4D04AED5BF61");
        const expectedPk = hexToBytes("01466BFAB55C54604D05E81FDD989C1A9DC2B8BDF6FDC9292F1AFC03CE776F2B0B00A9D61F67EB711A2A60F1D039706C232445D53EE490F3B8CFFA56E4993453A01F");
        const expectedSign = hexToBytes("53D079D74DC18E39EC77624A53D37E94139F7532B102FB0F25F7FAC47225CC444AF794A4A352DC399142799B6BDF1C989865BB666F711A248429BCEE2E11BC20");

        performTest(dstu257, privateKey, digest, rand, expectedPk, expectedSign);
    }, 10000);

    test("#3 (m=431)", () => {
        const privateKey = hexToBytes("B307AF47E9D37D53A9FCBF6D6E9E09340F580F903FE48A84BBF77B0BF7AB379507E04CE4A8EA29124910F1AB161A0E690B3AC1329609");
        const rand = hexToBytes("11192EA98A66020ED4ED319299F8FA0654F05C7313F9CB8BE5FC1972E0CD9ABB111EC61671BB4E5D812389C7D49BBEFEE36B180778EB");
        const expectedPk = hexToBytes("7182F9A71CAB6ACC5F650A3DFD3ADF0052F385F5E2C32C158DF234A394E37AA78FFC5B4ADCB37628FDB574A6D747A76436DD288327E33D16DD1C37158B607F400B81E80FB6F07F1F2FB05FD1184FD6092AD3573A86D94DB71823A68EA22DF572DE486829AC9C5CA1396A3EAA");
        const expectedSign = hexToBytes("2478B995ED4E4405B40BDE52C41AFDDD5E23806909D1F5E5A36A0994A497C53120CD94CC0CCB952BCA4B31598677B95254EA9BBFF189167A47E45FC11FE1F8340900DA1544D5C281F03AB13F9940571D61EABEF2F78CD8C46F89EA1A055BF5381A53712890CE76D17FF99244");

        performTest(dstu431, privateKey, digest, rand, expectedPk, expectedSign);
    }, 10000);
});

describe("[CORE] DSTU 4145-2002 (ONB)", () => {
    const digest = hexToBytes("2A681ECE118389B27A108137187EA862117EF1484289470ECAC802C5A651FDA8");

    test("#1 (m=173)", () => {
        const dstu173_onb_test = dstu4145(DSTU_173_ONB_TEST);
        const privateKey = hexToBytes("049FF09C848613AEA23699F78C960D5174617311ADCC");
        const rand = hexToBytes("070516411E5D9886B8486ECE54A30E9403D103B95F90");
        const expectedPk = hexToBytes("16C1FF796B32D6D2FC83CA9530B368B322F7874B2D011F253334197826B6ADAE44EDEAA7EA281D1C5E597A37");
        const expectedSign = hexToBytes("0472EA56AE478F95F1EC9F628FF43857E168B50FB8190477ECC260F390FB6D0AE4AE3B7A78120F8EC458EF9A");

        performTest(dstu173_onb_test, privateKey, digest, rand, expectedPk, expectedSign);
    }, 10000);
});