# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs
#
# Developer dependencies. `brew bundle` installs them; `make bootstrap` then adds
# the pnpm packages and the git hooks. Xcode is not a formula: install the
# version in .xcode-version via the App Store or the xcodes CLI below.

# Native build + lint toolchain
brew "cmake"        # the Windows CNG core (C++) build system
brew "llvm"         # clang-format, clang-tidy, and clangd for the C++ side
brew "swiftlint"    # Swift lint, reads .swiftlint.yml
brew "swiftformat"  # Swift format, reads .swiftformat
brew "ktlint"       # Kotlin lint (android and kmp)
brew "detekt"       # Kotlin static analysis, reads detekt.yml
brew "gradle"       # the Android + KMP build system
brew "doxygen"      # the C++ API documentation gate

# JavaScript workspace
brew "node"
brew "pnpm"

# Git hooks and the toolchain pin
brew "lefthook"     # the commit-message and formatting hooks (lefthook.yml)
brew "xcodes"       # installs and selects the Xcode in .xcode-version

# Flutter toolchain
cask "flutter"
