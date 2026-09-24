---

kanban-plugin: board
---

## Backlog

- [ ] T09 CRUD узлов + пересчет длин (TreeCoordinator-порт) #P2 #editor
- [ ] T10 Dock как VSCode (drag-drop, save layout) #P2 #ui
- [ ] T11 PFX/шифрованные ключи + печать/export #P2 #formats

## P0 Фундамент

(пусто — все в работе/готово)

## P1 Viewer MVP

- [ ] T06 Тип-бейдж + конвертер PEM↔DER↔Hex #P1 #formats
- [ ] T07 Cert-view как Windows + хеши узла #P1 #certview
- [ ] T08 Табы + split v/h + session backup #P1 #ui

## In Progress

- [ ] Установить Go 1.25 + Node 20 + Wails CLI (блокер: `go not found`) #setup

## Done

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
