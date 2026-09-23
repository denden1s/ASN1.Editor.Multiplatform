# ASN1 Editor — План (Go + Wails v2)

Решения grill-me (23.09.2026):
- GUI: Wails v2 (Go-бэкенд + WebView, React UI). Fyne отклонен, Wails v3 — только миграция позже.
- MVP: Viewer (дерево+hex+дампы+конвертер+тип+cert-view). Editor CRUD — этап 2.
- Форматы MVP: максимум как WPF — DER + PEM все ~24 шапки + Hex/Base64 raw, типы X.509/CSR/CRL/PKCS7/ключи.
- Архитектура: `internal/asn1` (TLV core самопис) + `pkg/oid` + `pkg/detect` + `pkg/certview` + `cmd/asn1cli` + `app` (Wails).
- Тип файла: бейдж по PEM-шапке + OID-эвристика, полный cert-view как в Windows.
- Вкладки: табы + split v/h, синхронизация дерево↔hex. Полный dock — позже.
- Самопис vs lib: TLV/DER-парсер + OID-резолв — самопис; `encoding/asn1`, `encoding/pem`, хеши — stdlib; React дерево/hex/табы — готовые компоненты.
- Obsidian: KANBAN.md в формате obsidian-kanban. Git: локальный init сейчас, GitHub remote — после того как дашь URL.

## Этапы и приоритетность (11 задач)

### P0 — Фундамент
- [ ] T01 Core TLV-парсер: DER Tag-Length-Value, long-form lengths, все universal-типы, сырое дерево (offset/header/payload/depth/tagName). Тесты на векторах openssl/test/certs.
- [ ] T02 Автодетект входа: DER? иначе AnyToBinary (HEX→PEM/Base64→binary) как FileUtility.cs:33. ~24 PEM-шапок + 5 Hex + Base64.
- [ ] T03 OID-словарь: порт OID.txt (846) + резолв + пользовательский словарь add/remove/save.

### P1 — Viewer MVP (Wails v2)
- [ ] T04 Wails v2 скелет: Go 1.25 + Node, `app` + `cmd/asn1cli` (open/save/export). Сборка mac/win/linux.
- [ ] T05 Дерево + hex + asn1parse-dump: OpenSSLFormatter (offset|length|lenbyte+indent) + HexViewer + скролл-синхрон.
- [ ] T06 Тип-бейдж + конвертер PEM↔DER↔Hex/Base64 с детектом.
- [ ] T07 Cert-view как в Windows: Subject/Issuer/Validity/Serial/SAN/EKU/Constraints, вкладка рядом с деревом + хеши узла (MD5/SHA1/256/384/512 hex/base64 TLV vs payload).
- [ ] T08 Табы + split v/h: несколько файлов, session-backup/recovery, CLI-аргументы.

### P2 — Editor (после viewer)
- [ ] T09 CRUD узлов: add/insert(before/after/last)/remove/update + пересчет length-байт и сдвиг offset/path (TreeCoordinator.cs:29), типизированные редакторы + валидаторы (bool/int/OID/time/bitstring).
- [ ] T10 Dock как VSCode: drag-drop панели, save layout (dockview/rc-dock).
- [ ] T11 PFX/шифрованные ключи, печать, export text+bin, полный паритет WPF.

## Ограничения / риски
- Go не установлен (`go: command not found`) — нужен Go 1.25 + Node 20 + Wails CLI. Linux-сборка требует WebKitGTK — только на нативных раннерах/CI.
- Wails v2 → v3 миграция beta — закладываем тонкий бэкенд чтобы переехать безболезненно.
- `encoding/asn1` Go не умеет raw TLV со сдвигами — только для декода значений, каркас TLV самописный.
- reference/ — только оракул (asn1parse.c, crypto/asn1, certs-пемки), в сборку не тащим.

## Следующий шаг
Установить Go → T01 → T02 → T03 → T04...
Каждый коммит = одна фича (T01..T11).
