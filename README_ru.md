<p align="center">
    <b>@li0ard/dstu</b><br>
    <b>Алгоритмы ДСТУ на чистом TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/dstu">документация</a>
    <br><br>
    <a href="https://github.com/li0ard/dstu/actions/workflows/test.yml"><img src="https://github.com/li0ard/dstu/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/dstu/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/dstu" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/dstu"><img src="https://img.shields.io/npm/v/@li0ard/dstu" /></a>
    <br>
    <hr>
</p>

## Установка

```bash
npm i @li0ard/dstu
```

## Поддерживаемые алгоритмы

- Эллиптические кривые и ЭП (ДСТУ 4145-2005, экспериментально)
- Шифр "Калина" (ДСТУ 7624:2014)
- Хэш-функция "Купина" (ДСТУ 7564:2014)
    - Supports KMAC
- Шифр "Струмок" (ДСТУ 8845:2019)

## Поддерживаемые режимы шифров

- Режим простой замены с зацеплением (CBC)
- Режим гаммирования с обратной связью по шифртексту (CFB)
- Режим гаммирования (CTR)
- Режим простой замены (ECB)
- Режим гаммирования с выработкой имитовставки (GCM)
- Режим выработки имитовставки (MAC and GMAC)
- Режим гаммирования с обратной связью по выходу (OFB)