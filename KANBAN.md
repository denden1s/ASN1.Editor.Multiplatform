---

kanban-plugin: board

---

## Backlog

- [ ] T09 CRUD узлов + пересчет длин (TreeCoordinator-порт) #P2 #editor
- [ ] T10 Dock как VSCode (drag-drop, save layout) #P2 #ui
- [ ] T11 PFX/шифрованные ключи + печать/export #P2 #formats


## P0 Фундамент



## P1 Viewer MVP

- [ ] T06 Тип-бейдж + конвертер PEM↔DER↔Hex (нужен бэкенд convert + UI) #P1 #formats
- [x] T07 Cert-view как Windows + хеши узла (+ CSR-запросы в той же вкладке) #P1 #certview
- [ ] T08 Табы + split v/h + session backup (табы+DnD сделаны, остался split и backup) #P1 #ui


## In Progress


## Done

- [x] CSR-view UI (designer, tsc+vite green) #P1 #certview
- [x] CSR-view backend (PKCS#10, ReqView, signatureValid) #P1 #certview
- [x] T07b Cert-view UI + хеши (designer, tsc+vite green) #P1 #certview
- [x] T07a Cert-view backend + хеши (internal/certview, CertView/NodeHash) #P1 #certview
- [x] DnD чинка (EnableFileDrop + useDropTarget false) + no contextmenu #P1 #gui
- [x] Вкладки файлов + DnD пачкой (designer, tsc+vite green, часть T08) #P1 #gui
- [x] OCTET nested expansion (инлайн `TAG { ... }`, EOC-guard) #P1 #core
- [x] Сайдбар структуры + скрытие (VS Code) (designer, tsc+vite green) #P1 #gui
- [x] OCTET STRING printable/hex (tab/LF/CR + ` (0xHEX)`) #P1 #core
- [x] Установить Go 1.25 + Node 20 + Wails CLI на хост (для `wails dev`/GUI-сборки) #setup
- [x] BIT STRING только hex (`unused=N (0xHEX)`) #P1 #core
- [x] BIT STRING hex в value (`unused/set + (0xHEX)`) #P1 #core
- [x] T05c Показ значений в UI (designer, tsc+vite green) #P1 #gui
- [x] T05b Декод значений полей backend (internal/value + NodeDTO.value) #P1 #core
- [x] T05 Дерево+hex+dump UI (designer, tsc+vite green) #P1 #gui
- [x] T04 Wails v2 скелет (app+cli, bindings OpenFile/GetHex) #P1 #gui
- [x] T02 fix: дженерик PEM-шапки (ATTRIBUTE CERTIFICATE и любые) #P0 #formats
- [x] devcontainers backend+frontend (образы собраны, смок внутри зеленый) #setup
- [x] T03 OID-словарь (847 записей, user dict) (docker: vet/test green) #P0 #core
- [x] T02 Автодетект DER/PEM/Hex/Base64 (24 шапки, docker: vet/test green) #P0 #formats
- [x] T01 Core TLV-парсер DER + тесты (docker: gofmt/vet/test green) #P0 #core
- [x] requirements.md + grill-me решения (Wails v2, viewer MVP, max PEM, core lib) #setup
- [x] PLAN.md + KANBAN.md для Obsidian #setup




%% kanban:settings
```
{"kanban-plugin":"board"}
```
%%