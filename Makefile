# ASN1 Editor — сборка CLI и GUI под macOS / Linux / Windows.
#
# CLI (чистый Go, CGO off) кросс-компилируется с любого хоста:
#   make cli-macos | cli-linux | cli-windows | cli-all | cli   (нативный)
# GUI (Wails v2) собирается ТОЛЬКО на целевой ОС — таргеты app-*
# делегируют в app/Makefile и падают с понятной ошибкой не на своей ОС.

CLI_PKG := ./cmd/asn1cli
DIST    := dist
LDFLAGS := -s -w

.DEFAULT_GOAL := help

.PHONY: help cli cli-macos cli-linux cli-windows cli-all \
	app-macos app-macos-universal app-linux app-windows app-installer-windows \
	clean

help: ## показать таргеты
	@echo "CLI (кросс-компиляция с любого хоста):"
	@echo "  make cli-macos             asn1cli под macOS (arm64+amd64) -> dist/"
	@echo "  make cli-linux             asn1cli под Linux (amd64+arm64) -> dist/"
	@echo "  make cli-windows           asn1cli под Windows (amd64)     -> dist/"
	@echo "  make cli-all               всё выше разом"
	@echo "  make cli                   нативный бинарь под текущий хост"
	@echo "GUI (Wails, запускать НА целевой ОС):"
	@echo "  make app-macos             .app под macOS (текущий arch)"
	@echo "  make app-macos-universal   .app под macOS (arm64+amd64)"
	@echo "  make app-linux             бинарь под Linux"
	@echo "  make app-windows           .exe под Windows"
	@echo "  make app-installer-windows установщик Windows (NSIS)"
	@echo "  make clean                 удалить dist/"

# --- CLI: матрица ос/arch -------------------------------------------------
cli-macos:
	@mkdir -p $(DIST)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/asn1cli-darwin-arm64 $(CLI_PKG)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/asn1cli-darwin-amd64 $(CLI_PKG)

cli-linux:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/asn1cli-linux-amd64 $(CLI_PKG)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/asn1cli-linux-arm64 $(CLI_PKG)

cli-windows:
	@mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/asn1cli-windows-amd64.exe $(CLI_PKG)

cli-all: cli-macos cli-linux cli-windows ## все CLI-бинари

cli: ## нативный CLI под текущий хост
	@mkdir -p $(DIST)
	@exe=""; [ "$$(go env GOOS)" = windows ] && exe=".exe"; \
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/asn1cli$$exe $(CLI_PKG)

# --- GUI: только делегирование в app/Makefile ------------------------------
app-macos:
	$(MAKE) -C app build-macos

app-macos-universal:
	$(MAKE) -C app build-macos-universal

app-linux:
	$(MAKE) -C app build-linux

app-windows:
	$(MAKE) -C app build-windows

app-installer-windows:
	$(MAKE) -C app installer-windows

clean: ## удалить dist/
	rm -rf $(DIST)
