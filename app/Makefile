# ASN1 Editor GUI (Wails v2).
# Wails НЕ кросс-компилирует GUI: каждый build-*-таргет запускать НА своей ОС.
# Проверки ниже падают с понятной ошибкой, а не с кашей из CGO/WebKit.
#
#   macOS:   make build-macos[. -universal]   (нужны Xcode CLT, Go, Node, wails)
#   Linux:   make build-linux                 (libgtk-3-dev, libwebkit2gtk-4.1-dev, ...)
#   Windows: make build-windows | installer-windows   (MSVC/WebView2, NSIS для установщика)

UNAME_S := $(shell uname -s)

.DEFAULT_GOAL := help

.PHONY: help build dev frontend generate \
	build-macos build-macos-universal build-linux build-windows installer-windows \
	clean

help: ## показать таргеты
	@echo "  make build                   сборка под ТЕКУЩИЙ хост (wails build)"
	@echo "  make dev                     wails dev (хот-релоад)"
	@echo "  make build-macos             macOS .app (запускать на macOS)"
	@echo "  make build-macos-universal   macOS .app arm64+amd64 (запускать на macOS)"
	@echo "  make build-linux             Linux-бинарь (запускать на Linux)"
	@echo "  make build-windows           Windows .exe (запускать на Windows)"
	@echo "  make installer-windows       Windows-установщик NSIS (запускать на Windows)"
	@echo "  make frontend                только пересборка фронта (npm)"
	@echo "  make generate                реген wailsjs-биндингов"
	@echo "  make clean                   удалить build/bin и frontend/dist"

build: ## сборка под текущий хост
	wails build

dev: ## dev-режим с хот-релоадом
	wails dev

frontend: ## только фронт: npm install + build -> frontend/dist
	cd frontend && npm install --no-audit --no-fund && npm run build

generate: ## регенерировать wailsjs после смены Go-биндингов
	wails generate module

# --- Per-OS, со сторожами ---------------------------------------------------
build-macos: ## macOS .app (только на macOS)
	@if [ "$(UNAME_S)" != Darwin ]; then \
	  echo "ERROR: build-macos запускать НА macOS (wails не кросс-компилирует GUI)."; exit 1; fi
	wails build -platform darwin

build-macos-universal: ## macOS .app arm64+amd64 (только на macOS)
	@if [ "$(UNAME_S)" != Darwin ]; then \
	  echo "ERROR: build-macos-universal запускать НА macOS."; exit 1; fi
	wails build -platform darwin/universal

build-linux: ## Linux-биOpenBinary (только на Linux)
	@if [ "$(UNAME_S)" != Linux ]; then \
	  echo "ERROR: build-linux запускать НА Linux (нужны GTK/WebKitGTK)."; exit 1; fi
	wails build -platform linux

build-windows: ## Windows .exe (только на Windows)
	@case "$(UNAME_S)" in MINGW*|MSYS*|CYGWIN*) ;; *) \
	  echo "ERROR: build-windows запускать НА Windows."; exit 1;; esac
	wails build -platform windows

installer-windows: ## Windows-установщик через NSIS (только на Windows)
	@case "$(UNAME_S)" in MINGW*|MSYS*|CYGWIN*) ;; *) \
	  echo "ERROR: installer-windows запускать НА Windows (нужен NSIS)."; exit 1;; esac
	wails build -platform windows -nsis

clean: ## снести артефакты сборки GUI
	rm -rf build/bin frontend/dist
