# ASN1 Editor

Кроссплатформенный редактор ASN.1/DER: дерево TLV, hex-дамп, семантический просмотр X.509-сертификатов и CSR-запросов, хеши узлов.

Go 1.25 + Wails v2 (нативный WebView) в GUI, React 19 + TypeScript 5 на Vite 7 во фронтенде, чистое Go-ядро без внешних ASN.1-зависимостей.

## Возможности

**Ядро**
- Строгий DER TLV-парсер с проверкой длин, тегов и вложенности
- Автоопределение формата: DER, PEM (24 типа шапок), Hex, Base64
- Словарь OID на 847 записей + пользовательский словарь
- Декодирование значений полей: INTEGER, BIT STRING, OCTET STRING, PrintableString и прочие
- Семантический разбор сертификатов (X.509) и запросов (PKCS#10)
- Хеши узлов: MD5, SHA-1, SHA-256, SHA-384, SHA-512

**GUI**
- Дерево структуры + hex-дамп + ASCII-дамп с подсветкой по выбранному узлу
- Раскрытие вложенного DER внутри OCTET STRING по месту (`30 { ... }`)
- Вкладки Cert / Hex / Dump с семантическим видом сертификата: subject, issuer, SAN, сроки, key usage, EKU, отпечатки
- Просмотр CSR: subject, запрошенные расширения, атрибуты, проверка самоподписи
- Панель хешей выбранного узла
- Вкладки файлов, перетаскивание нескольких файлов сразу
- Сайдбар структуры — `Ctrl/Cmd+B`, состояние сохраняется

## Требования

Для сборки GUI нужен системный WebView:

| ОС | Пакеты |
|---|---|
| macOS | Xcode Command Line Tools |
| Debian/Ubuntu | `libgtk-3-dev libwebkit2gtk-4.1-dev pkg-config gcc` |
| Fedora | `gtk3-devel webkit2gtk4.1-devel` |
| Arch | `gtk3 webkit2gtk-4.1` |
| Windows | WebView2 + MSVC |

Плюс Go 1.25+, Node 20+, Wails CLI:

```sh
go install github.com/wailsapp/wails/v2/cmd/wails@latest
```

Для запуска готового бинаря Linux достаточно рантайм-пакетов `libgtk-3-0` и `libwebkit2gtk-4.1-0`.

## Сборка

GUI через Wails не кросс-компилируется — каждый target собирается на своей ОС.

```sh
make app-macos             # macOS .app
make app-macos-universal   # macOS arm64 + amd64
make app-linux             # Linux-бинарь (на Linux)
make app-windows           # Windows .exe (на Windows)
make app-installer-windows # установщик NSIS (на Windows)
```

CLI — чистый Go, собирается с любого хоста:

```sh
make cli-all               # macOS, Linux, Windows сразу в dist/
make cli-linux             # только Linux (amd64 + arm64)
```

Таргеты GUI валятся с понятной ошибкой, если запущены не на своей ОС.

## Запуск в разработке

```sh
cd app && wails dev
```

Горячая перезагрузка фронтенда — автоматически. Изменения в `app/main.go` требуют полного рестарта.

## CLI

```sh
asn1cli <file>
```

Печатает определённый формат, метку PEM, тип файла и верхний уровень структуры:

```
encoding: PEM
label: CERTIFICATE
typehint: certificate
root: offset=0 tag=SEQUENCE length=812
  child: offset=4 tag=[0] length=763
  ...
```

## Структура

```
internal/asn1      TLV-парсер
internal/detect    автоопределение формата
internal/oid       словарь OID и резолвер
internal/value     декодирование значений
internal/certview  разбор сертификатов и CSR
cmd/asn1cli        CLI
app/               Wails-приложение (React + TypeScript)
```

## Тесты

```sh
make test
```

## Статус

Готов Viewer MVP: TLV-дерево, hex/дамп, cert-view, CSR-view, хеши, вкладки и drag-and-drop. В работе — конвертер форматов, split-панели, редактирование узлов.