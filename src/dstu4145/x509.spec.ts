import { bytesToHex, type CHash } from "@noble/hashes/utils.js";
import { AsnConvert, AsnIntegerArrayBufferConverter, AsnProp, AsnPropTypes, AsnType, AsnTypeTypes, OctetString } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import { describe, test, expect } from "bun:test";
import { dstu4145, expandPoint } from ".";
import { gost3431195 } from "@li0ard/gost/gost341194.js";
import { kupyna256, kupyna384, kupyna512 } from "../kupyna";

// ASN.1 schemes from https://zakon.rada.gov.ua/laws/show/z1398-12#Text
export class Pentanomial {
    @AsnProp({ type: AsnPropTypes.Integer })
    k!: number;

    @AsnProp({ type: AsnPropTypes.Integer })
    j!: number;

    @AsnProp({ type: AsnPropTypes.Integer })
    l!: number;

    constructor(params: Partial<Pentanomial> = {}) {
        Object.assign(this, params);
    }
}

@AsnType({ type: AsnTypeTypes.Choice })
export class BinaryFieldPolynomial {

    @AsnProp({ type: AsnPropTypes.Integer })
    trinomial?: number;

    @AsnProp({ type: Pentanomial })
    pentanomial?: Pentanomial;

    constructor(params: Partial<BinaryFieldPolynomial> = {}) {
        Object.assign(this, params);
    }
}

export class BinaryField {
    @AsnProp({ type: AsnPropTypes.Integer })
    m!: number;

    @AsnProp({ type: BinaryFieldPolynomial, optional: true })
    poly?: BinaryFieldPolynomial;

    constructor(params: Partial<BinaryField> = {}) {
        Object.assign(this, params);
    }
}

export class ECBinary {
    @AsnProp({ type: BinaryField })
    f!: BinaryField;

    @AsnProp({ type: AsnPropTypes.Integer })
    a!: 0 | 1;

    @AsnProp({ type: AsnPropTypes.OctetString })
    b!: ArrayBuffer;

    @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
    n!: ArrayBuffer;

    @AsnProp({ type: AsnPropTypes.OctetString })
    bp!: ArrayBuffer;

    constructor(params: Partial<ECBinary> = {}) {
        Object.assign(this, params);
    }
}

@AsnType({ type: AsnTypeTypes.Choice })
export class DSTU4145ParamsCurve {
    @AsnProp({ type: ECBinary })
    ecbinary?: ECBinary;

    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    namedCurve?: string

    constructor(params: Partial<DSTU4145ParamsCurve> = {}) {
        Object.assign(this, params);
    }
}

export class DSTU4145Params {
    @AsnProp({ type: DSTU4145ParamsCurve })
    curve!: DSTU4145ParamsCurve;

    @AsnProp({ type: AsnPropTypes.OctetString, optional: true })
    dke?: ArrayBuffer;

    constructor(params: Partial<DSTU4145Params> = {}) {
        Object.assign(this, params);
    }
}

const createSignerFromParameters = (params: ECBinary) => {
    if(!params.f.poly) throw new Error("Missing poly coefficients");
    const m = params.f.m;
    const ks: number[] = params.f.poly.pentanomial
        ? Object.values(params.f.poly.pentanomial)
        : [params.f.poly.trinomial!];

    const a = params.a;
    const b = bytesToHex(new Uint8Array(params.b).reverse());
    const order = bytesToHex(new Uint8Array(params.n));

    const G = expandPoint(
        new Uint8Array(params.bp).reverse(),
        { m, ks, a, b }
    );

    return dstu4145({
        m, ks, a, b, order,
        Gx: bytesToHex(G.x),
        Gy: bytesToHex(G.y)
    });
}

const proceedCertificate = (certificate: Uint8Array) => {
    const parsed = AsnConvert.parse(certificate, Certificate);
    
    const spki = parsed.tbsCertificate.subjectPublicKeyInfo;
    const parameters = AsnConvert.parse(spki.algorithm.parameters!, DSTU4145Params);
    if(!parameters.curve.ecbinary) throw new Error("Missing curve definition");
    const signer = createSignerFromParameters(parameters.curve.ecbinary);

    const spk = new Uint8Array(AsnConvert.parse(spki.subjectPublicKey, OctetString).buffer).reverse();

    let hash: CHash;
    switch(parsed.signatureAlgorithm.algorithm) {
        case "1.2.804.2.1.1.1.1.3.1.1":
            hash = gost3431195;
        break;
        case "1.2.804.2.1.1.1.1.3.6.1.1":
            hash = kupyna256;
        break;
        case "1.2.804.2.1.1.1.1.3.6.2.1":
            hash = kupyna384;
        break;
        case "1.2.804.2.1.1.1.1.3.6.3.1":
            hash = kupyna512;
        break;
        default:
            hash = gost3431195;
    }

    const digest = hash(new Uint8Array(parsed.tbsCertificateRaw!)).reverse();
    const signature = new Uint8Array(AsnConvert.parse(parsed.signatureValue, OctetString).buffer).reverse();

    expect(signer.verify(spk, digest, signature)).toBeTrue();
}

describe("[X.509] DSTU 4145-2002 (PB)", () => {
    test("#1 (m=431, gost3431195)", () => {
        // Міністерство цифрової трансформації України (S/N 352334916528167280787939677242593120895084003328)
        // https://czo.gov.ua/download/cacertificates/CZO-ROOT-2017.cer
        const certificate = `
MIIFZTCCBOGgAwIBAgIUPbc+e/DVdbIBAAAAAQAAAIEAAAAwDQYLKoYkAgEBAQEDAQEwgfoxPzA9BgNV
BAoMNtCc0ZbQvdGW0YHRgtC10YDRgdGC0LLQviDRjtGB0YLQuNGG0ZbRlyDQo9C60YDQsNGX0L3QuDEx
MC8GA1UECwwo0JDQtNC80ZbQvdGW0YHRgtGA0LDRgtC+0YAg0IbQotChINCm0JfQnjFJMEcGA1UEAwxA
0KbQtdC90YLRgNCw0LvRjNC90LjQuSDQt9Cw0YHQstGW0LTRh9GD0LLQsNC70YzQvdC40Lkg0L7RgNCz
0LDQvTEZMBcGA1UEBQwQVUEtMDAwMTU2MjItMjAxNzELMAkGA1UEBhMCVUExETAPBgNVBAcMCNCa0LjR
l9CyMB4XDTE3MDkyMjA3MTkwMFoXDTI3MDkyMjA3MTkwMFowgfoxPzA9BgNVBAoMNtCc0ZbQvdGW0YHR
gtC10YDRgdGC0LLQviDRjtGB0YLQuNGG0ZbRlyDQo9C60YDQsNGX0L3QuDExMC8GA1UECwwo0JDQtNC8
0ZbQvdGW0YHRgtGA0LDRgtC+0YAg0IbQotChINCm0JfQnjFJMEcGA1UEAwxA0KbQtdC90YLRgNCw0LvR
jNC90LjQuSDQt9Cw0YHQstGW0LTRh9GD0LLQsNC70YzQvdC40Lkg0L7RgNCz0LDQvTEZMBcGA1UEBQwQ
VUEtMDAwMTU2MjItMjAxNzELMAkGA1UEBhMCVUExETAPBgNVBAcMCNCa0LjRl9CyMIIBUTCCARIGCyqG
JAIBAQEBAwEBMIIBATCBvDAPAgIBrzAJAgEBAgEDAgEFAgEBBDbzykDGaaTaFzFJyhLDLa4Ya1Osa8Y2
WZferq6K0tiI+b/VNAFpTvnEJz2M/m3Cj3BqD0kQzgMCNj//////////////////////////////////
/7oxdUWACajApyTwL4Gqih/Lr4DZDHqVEQUEzwQ2fIV8lMVDO/2ZHhfCJoQGWFCpoknte8JJrlpOh4aJ
+HLvetUkCC7DA46a7ee6a6Ezgdl5umIaBECp1utF8TxwgoDElnsjH16t9ljrpMA3KR042WvwJcpOF/jp
cg3GFbQ6KJdfC8Heo2Q4tWTqLBef0BI+bbj6xXkEAzkABDYb4w66IKfDEdOz7rn4zYcIy8/GXTJJVLpK
Pm/sjnb255xZPsT7pzixk608EPRZzbQulpa+fhOjggFEMIIBQDApBgNVHQ4EIgQgvbc+e/DVdbJIAng9
ngWpUJd2wXX3rIF2dAgHlno0IBQwKwYDVR0jBCQwIoAgvbc+e/DVdbJIAng9ngWpUJd2wXX3rIF2dAgH
lno0IBQwDgYDVR0PAQH/BAQDAgEGMBkGA1UdIAEB/wQPMA0wCwYJKoYkAgEBAQICMBIGA1UdEwEB/wQI
MAYBAf8CAQIwHgYIKwYBBQUHAQMBAf8EDzANMAsGCSqGJAIBAQECATBCBgNVHR8EOzA5MDegNaAzhjFo
dHRwOi8vY3pvLmdvdi51YS9kb3dubG9hZC9jcmxzL0NaTy0yMDE3LUZ1bGwuY3JsMEMGA1UdLgQ8MDow
OKA2oDSGMmh0dHA6Ly9jem8uZ292LnVhL2Rvd25sb2FkL2NybHMvQ1pPLTIwMTctRGVsdGEuY3JsMA0G
CyqGJAIBAQEBAwEBA28ABGyM+R9vCn1p+BoSw0fYUfnSiIGNAuro/T7ujYr/i4go9DU/7EJrVfCnPQwH
TeHTTxPZnllXPRESmRr+4SjSUJ/Fs9jBqpDuH+tmUUNsB+TT7YfUPs6evaP52j9ud+gFQmS5COCTKdOT
cEeAViI=
        `;

        proceedCertificate(Uint8Array.fromBase64(certificate));
    }, 10000);

    test("#2 (m=431, kupyna256)", () => {
        // Міністерство цифрової трансформації України (S/N 497644508731761117376205752830329139982944501760)
        // https://czo.gov.ua/download/cacertificates/CAO-2026.cer
        const certificate = `
MIIGJDCCBZ+gAwIBAgIUVysmy9RtZkoBAAAAAQAAAK4BAAAwDgYMKoYkAgEBAQEDBgEBMIIBMDFcMFoG
A1UECgxT0JzRltC90ZbRgdGC0LXRgNGB0YLQstC+INGG0LjRhNGA0L7QstC+0Zcg0YLRgNCw0L3RgdGE
0L7RgNC80LDRhtGW0Zcg0KPQutGA0LDRl9C90LgxMTAvBgNVBAsMKNCQ0LTQvNGW0L3RltGB0YLRgNCw
0YLQvtGAINCG0KLQoSDQptCX0J4xSTBHBgNVBAMMQNCm0LXQvdGC0YDQsNC70YzQvdC40Lkg0LfQsNGB
0LLRltC00YfRg9Cy0LDQu9GM0L3QuNC5INC+0YDQs9Cw0L0xGTAXBgNVBAUTEFVBLTQzMjIwODUxLTI2
MDExCzAJBgNVBAYTAlVBMREwDwYDVQQHDAjQmtC40ZfQsjEXMBUGA1UEYQwOTlRSVUEtNDMyMjA4NTEw
HhcNMjYwMTI3MTQ0NDAwWhcNMzYwMTI3MTQ0NDAwWjCCATAxXDBaBgNVBAoMU9Cc0ZbQvdGW0YHRgtC1
0YDRgdGC0LLQviDRhtC40YTRgNC+0LLQvtGXINGC0YDQsNC90YHRhNC+0YDQvNCw0YbRltGXINCj0LrR
gNCw0ZfQvdC4MTEwLwYDVQQLDCjQkNC00LzRltC90ZbRgdGC0YDQsNGC0L7RgCDQhtCi0KEg0KbQl9Ce
MUkwRwYDVQQDDEDQptC10L3RgtGA0LDQu9GM0L3QuNC5INC30LDRgdCy0ZbQtNGH0YPQstCw0LvRjNC9
0LjQuSDQvtGA0LPQsNC9MRkwFwYDVQQFExBVQS00MzIyMDg1MS0yNjAxMQswCQYDVQQGEwJVQTERMA8G
A1UEBwwI0JrQuNGX0LIxFzAVBgNVBGEMDk5UUlVBLTQzMjIwODUxMIIBDTCBzwYLKoYkAgEBAQEDAQEw
gb8wgbwwDwICAa8wCQIBAQIBAwIBBQIBAQQ288pAxmmk2hcxScoSwy2uGGtTrGvGNlmX3q6uitLYiPm/
1TQBaU75xCc9jP5two9wag9JEM4DAjY///////////////////////////////////+6MXVFgAmowKck
8C+Bqoofy6+A2Qx6lREFBM8ENnyFfJTFQzv9mR4XwiaEBlhQqaJJ7XvCSa5aToeGifhy73rVJAguwwOO
mu3numuhM4HZebpiGgM5AAQ2X8l6Y4f4w5NU6BvJAZkAnQ2W7phbTWrUVnxkZ1SJI8Z6sGbeYax71WM9
lPqmRNc/2CufY5sWo4IB1zCCAdMwKQYDVR0OBCIEINcrJsvUbWZKjXvtf13+2aoC/PxoWYXKbHFhD+gn
SfkBMCsGA1UdIwQkMCKAINcrJsvUbWZKjXvtf13+2aoC/PxoWYXKbHFhD+gnSfkBMA4GA1UdDwEB/wQE
AwIBBjAXBgNVHSUEEDAOBgwrBgEEAYGXRgEBCB8wPAYDVR0gBDUwMzAxBgkqhiQCAQEBAgIwJDAiBggr
BgEFBQcCARYWaHR0cHM6Ly9jem8uZ292LnVhL2NwczASBgNVHRMBAf8ECDAGAQH/AgECMHUGCCsGAQUF
BwEDBGkwZzAIBgYEAI5GAQEwCAYGBACORgEEMCoGBgQAjkYBBTAgMB4WGGh0dHBzOi8vY3pvLmdvdi51
YS9hYm91dBMCZW4wDgYGBACORgEHMAQTAlVBMBUGCCsGAQUFBwsCMAkGBwQAi+xJAQIwQgYDVR0fBDsw
OTA3oDWgM4YxaHR0cDovL2N6by5nb3YudWEvZG93bmxvYWQvY3Jscy9DWk8tMjAyNi1GdWxsLmNybDBD
BgNVHS4EPDA6MDigNqA0hjJodHRwOi8vY3pvLmdvdi51YS9kb3dubG9hZC9jcmxzL0NaTy0yMDI2LURl
bHRhLmNybDAOBgwqhiQCAQEBAQMGAQEDbwAEbIq7vg3ge0oqtJuuKzlOYUT+4bt2TbY+DrGknxdEfREU
XALU/e7yOvDvv6nuDZILtMmRs5Q1CUqPaaYnwWlYizp+MRG4jDi9GCyHPjO5xcIXX+c9uyAxLB/9oLD1
5sDbIlnGHTxiy54Btr0/Pg==
        `;

        proceedCertificate(Uint8Array.fromBase64(certificate));
    }, 10000);
});