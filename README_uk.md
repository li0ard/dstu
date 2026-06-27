<p align="center">
    <b>@li0ard/dstu</b><br>
    <b>Алгоритми ДСТУ на чистому TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/dstu">документація</a>
    <br><br>
    <a href="https://github.com/li0ard/dstu/actions/workflows/test.yml"><img src="https://github.com/li0ard/dstu/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/dstu/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/dstu" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/dstu"><img src="https://img.shields.io/npm/v/@li0ard/dstu" /></a>
    <br>
    <hr>
</p>

## Встановлення

```bash
npm i @li0ard/dstu
```

## Підтримувані алгоритми

- Еліптичні криві та ЕП (ДСТУ 4145-2005, експериментально)
- Шифр "Калина" (ДСТУ 7624:2014)
- Геш-функція "Купина" (ДСТУ 7564:2014)
    - Підтримує KMAC
- Шифр "Струмок" (ДСТУ 8845:2019)

## Підтримувані режими шифрування

- Зчеплення шифроблоків (CBC)
- Гамування зі зворотним зв'язком за шифротекстом (CFB)
- Гамування (CTR)
- Проста заміна (ECB)
- Вибіркове гамування із прискореним виробленням імітовставки (GCM)
- Вироблення імітовставки (MAC and GMAC)
- Гамування зі зворотним зв'язком за шифрогамою (OFB)