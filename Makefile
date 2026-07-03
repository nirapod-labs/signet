# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs
#
# Primary command surface. Delegates to each ecosystem's own build tool
# (swift, gradle, flutter, pnpm/nitrogen). Turbo caches the JS tasks.

SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help bootstrap lint format conformance \
        build build-apple build-android \
        build-flutter build-rn build-kmp \
        test test-apple test-android clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

bootstrap: ## Install dev deps (brew + pnpm) and git hooks
	brew bundle
	pnpm install
	pnpm exec lefthook install

lint: ## Lint the JS/TS/JSON surface (Biome)
	pnpm exec biome check .

format: ## Format the JS/TS/JSON surface (Biome)
	pnpm exec biome format --write .

conformance: ## Run the cross-language conformance suite
	node conformance/harness/driver.mjs

build: build-apple build-android ## Build the v1 native cores

build-apple: ## Build the Apple core (SPM)
	cd apple && swift build

build-android: ## Build the Android core (Gradle)
	cd android && ./gradlew assemble

build-flutter: ## Fetch and analyze the Flutter plugin
	cd flutter/signet && flutter pub get && flutter analyze

build-rn: ## Install and run Nitrogen codegen for the RN binding
	cd react-native/react-native-signet && pnpm install && pnpm run codegen

build-kmp: ## Build the KMP binding
	cd kmp/signet && ./gradlew build

test-apple: ## Test the Apple core
	cd apple && swift test

test-android: ## Test the Android core
	cd android && ./gradlew test

test: test-apple test-android conformance ## Run core tests and the conformance suite

clean: ## Remove build artifacts
	rm -rf apple/.build android/build flutter/signet/build \
		react-native/react-native-signet/lib kmp/signet/build
