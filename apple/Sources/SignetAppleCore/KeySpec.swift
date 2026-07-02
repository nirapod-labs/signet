// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

/// A key generation request. Tier is selected by `tierPolicy` (class-based, not
/// a concrete level); `accessControl` sets the presence check bound to the key.
public struct KeySpec: Sendable, Equatable {
    /// Stable, app-scoped name for the key.
    public let alias: String
    /// Tier selection. Defaults to `strongest`.
    public let tierPolicy: TierPolicy
    /// Access-control policy. Defaults to no presence check.
    public let accessControl: AccessControlPolicy

    public init(
        alias: String,
        tierPolicy: TierPolicy = .strongest,
        accessControl: AccessControlPolicy = .none
    ) {
        self.alias = alias
        self.tierPolicy = tierPolicy
        self.accessControl = accessControl
    }
}

/// An opaque reference to a generated key. It carries only the alias; the key
/// material stays in hardware and is addressed by name at the key store.
///
/// The initializer is public: a handle is a reconstructible token, not a live
/// reference. A binding that persisted the alias rebuilds the handle across
/// process restarts without holding the original object. Building a handle
/// grants no access on its own; it names a key, and `exists`, `delete`, and
/// `getSecurityTier` already address a key by alias.
public struct KeyHandle: Sendable, Equatable {
    public let alias: String

    public init(alias: String) {
        self.alias = alias
    }
}
