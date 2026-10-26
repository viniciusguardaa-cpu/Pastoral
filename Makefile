# Pastoral Makefile
# Usage:
#   make build       — debug build (app + helper + core + proxy)
#   make test        — run all unit + integration tests
#   make release     — release build (optimized)
#   make universal   — universal arm64 + x86_64 fat binaries
#   make app         — build .app bundle
#   make pkg         — build helper .pkg
#   make dmg         — build dist/Pastoral-<version>.dmg
#   make sign        — codesign with hardened runtime
#   make notarize    — notarize with notarytool
#   make lab         — run lab test network (Docker)
#   make clean       — clean build artifacts
#   make uninstall   — run the uninstaller (requires root)

VERSION := 1.1.1
DIST := dist
BUILD := .build
APP_NAME := Pastoral
APP_BUNDLE := $(DIST)/$(APP_NAME).app
HELPER_PKG := $(DIST)/pastoral-helper.pkg
DMG := $(DIST)/$(APP_NAME)-$(VERSION).dmg

# Signing identity (set via env or here)
SIGN_IDENTITY ?= -
NOTARY_PROFILE ?= pastoral

.PHONY: build test release universal app pkg dmg sign notarize lab clean uninstall

build:
	swift build

test:
	swift test

release:
	swift build -c release

# Universal arm64 + x86_64 fat binaries
universal:
	swift build -c release --arch arm64 --arch x86_64

# Build the .app bundle
app: pkg
	@echo "Building .app bundle..."
	@mkdir -p "$(APP_BUNDLE)/Contents/MacOS" "$(APP_BUNDLE)/Contents/Resources"
	@cp "$(BUILD)/release/Pastoral" "$(APP_BUNDLE)/Contents/MacOS/Pastoral"
	@cp Sources/Pastoral/Resources/* "$(APP_BUNDLE)/Contents/Resources/"
	@rm -rf "$(APP_BUNDLE)/Pastoral_Pastoral.bundle"
	@ditto "$(BUILD)/release/Pastoral_Pastoral.bundle" "$(APP_BUNDLE)/Contents/Resources/Pastoral_Pastoral.bundle"
	@cp "$(HELPER_PKG)" "$(APP_BUNDLE)/Contents/Resources/"
	@shasum -a 256 "$(BUILD)/release/pastoral-helper" | awk '{print $$1}' > "$(APP_BUNDLE)/Contents/Resources/helper.sha256"
	@sed 's/@VERSION@/$(VERSION)/g' Installer/Info.plist > "$(APP_BUNDLE)/Contents/Info.plist"
	@codesign --force --sign "$(SIGN_IDENTITY)" "$(APP_BUNDLE)"
	@echo "App bundle: $(APP_BUNDLE)"

# Build the helper .pkg
pkg:
	@PASTORAL_DIST_DIR="$(abspath $(DIST))" PASTORAL_VERSION="$(VERSION)" ./Scripts/build-pkg.sh

# Build the DMG with .app + .pkg + README.pdf
dmg: app
	@echo "Building DMG..."
	@mkdir -p "$(BUILD)/dmg-staging"
	@ditto "$(APP_BUNDLE)" "$(BUILD)/dmg-staging/Pastoral.app"
	@cp "$(HELPER_PKG)" README.md "$(BUILD)/dmg-staging/"
	@hdiutil create -volname "Pastoral" -srcfolder "$(BUILD)/dmg-staging" -ov -format UDZO "$(DMG)"
	@echo "DMG: $(DMG)"

# Codesign with hardened runtime
sign: app
	@echo "Signing app..."
	@codesign --options runtime --entitlements Entitlements.plist \
		--sign $(SIGN_IDENTITY) --force --deep $(APP_BUNDLE)
	@echo "Signed: $(APP_BUNDLE)"

# Notarize with notarytool
notarize: sign
	@echo "Notarizing..."
	@xcrun notarytool submit $(DMG) --keychain-profile $(NOTARY_PROFILE) --wait
	@xcrun stapler staple $(DMG)
	@echo "Notarized: $(DMG)"

# Lab: two-container test network for spoofing validation
lab:
	@echo "Starting lab test network..."
	@./Scripts/lab.sh

clean:
	swift package clean
	rm -rf $(DIST)

uninstall:
	@echo "Running uninstaller (requires root)..."
	@sudo sh Installer/scripts/uninstall.sh
