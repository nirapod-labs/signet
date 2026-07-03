// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

/// The prompt an auth-gated `sign` presents. Supplied per call for a gated key;
/// the Secure Enclave presents the biometric UI itself and authenticates the key
/// directly, which a caller-drawn prompt could not. `authRequirement` must match
/// the key's and selects the prompt's authenticators.
public struct AuthPrompt: Sendable, Equatable {
    /// The primary reason line shown in the biometric prompt.
    public let title: String
    /// An optional second line, appended below the title.
    public let subtitle: String?
    /// The cancel-button label.
    public let negativeButtonText: String
    /// The presence check the key was created with; selects the authenticators.
    public let authRequirement: AccessControlPolicy.AuthRequirement

    public init(
        title: String,
        subtitle: String? = nil,
        negativeButtonText: String = "Cancel",
        authRequirement: AccessControlPolicy.AuthRequirement
    ) {
        self.title = title
        self.subtitle = subtitle
        self.negativeButtonText = negativeButtonText
        self.authRequirement = authRequirement
    }
}
