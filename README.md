<p align="center">
    <b>@li0ard/dstu</b><br>
    <b>DSTU cryptography algorithms in pure TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/dstu">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/dstu/actions/workflows/test.yml"><img src="https://github.com/li0ard/dstu/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/dstu/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/dstu" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/dstu"><img src="https://img.shields.io/npm/v/@li0ard/dstu" /></a>
    <br>
    <hr>
</p>

## Installation

```bash
npm i @li0ard/dstu
```

## Supported algorithms

- Curves and DSA (DSTU 4145-2002, polynomial basis)
- Kalyna cipher (DSTU 7624:2014)
- Kupyna hash function (DSTU 7564:2014)
    - Supports KMAC
- Strumok stream cipher (DSTU 8845:2019)

## Supported cipher modes

- Cipher Block Chaining mode (CBC)
- Cipher Feedback mode (CFB)
- Counter mode (CTR)
- Electronic Codebook mode (ECB)
- Galois Counter mode (GCM)
- Message Authentication Code mode (MAC and GMAC)
- Output Feedback mode (OFB)