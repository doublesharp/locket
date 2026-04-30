//! V1 agent RPC method registry and wire-name parsing.

use std::str::FromStr;

use thiserror::Error;

/// V1 agent RPC method names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentMethod {
    /// Return metadata-only agent status.
    Status,
    /// Unlock local key material.
    Unlock,
    /// Clear local key material and live grants.
    Lock,
    /// Register an automation client.
    RegisterClient,
    /// Revoke an automation client.
    RevokeClient,
    /// Request a live TTL grant.
    RequestGrant,
    /// Revoke a live TTL grant.
    RevokeGrant,
    /// Lazily record an expired grant.
    ExpireGrant,
    /// Resolve an authorized `lk://` reference.
    ResolveReference,
    /// Prepare a command policy for execution.
    PrepareExec,
    /// Provide known-value scan matching.
    ScanKnownValues,
    /// List metadata-only runtime session rows.
    ListRuntimeSessions,
    /// List metadata-only saved command policy rows.
    ListPolicies,
    /// Reveal one secret value through a gated path.
    Reveal,
    /// Copy one secret value through a gated path.
    Copy,
    /// Verify the local audit HMAC chain.
    VerifyAudit,
    /// List metadata-only audit rows.
    ListAudit,
    /// Subscribe to metadata-only status events.
    SubscribeStatus,
    /// Cancel a status subscription.
    CancelSubscription,
    /// Automation client challenge handshake.
    ClientHello,
    /// Return metadata-only active-profile secret rows.
    ListSecrets,
    /// Return metadata-only secret version rows.
    ListVersions,
}

impl AgentMethod {
    /// Returns the exact v1 wire method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "Status",
            Self::Unlock => "Unlock",
            Self::Lock => "Lock",
            Self::RegisterClient => "RegisterClient",
            Self::RevokeClient => "RevokeClient",
            Self::RequestGrant => "RequestGrant",
            Self::RevokeGrant => "RevokeGrant",
            Self::ExpireGrant => "ExpireGrant",
            Self::ResolveReference => "ResolveReference",
            Self::PrepareExec => "PrepareExec",
            Self::ScanKnownValues => "ScanKnownValues",
            Self::ListRuntimeSessions => "ListRuntimeSessions",
            Self::ListPolicies => "ListPolicies",
            Self::Reveal => "Reveal",
            Self::Copy => "Copy",
            Self::VerifyAudit => "VerifyAudit",
            Self::ListAudit => "ListAudit",
            Self::SubscribeStatus => "SubscribeStatus",
            Self::CancelSubscription => "CancelSubscription",
            Self::ClientHello => "ClientHello",
            Self::ListSecrets => "ListSecrets",
            Self::ListVersions => "ListVersions",
        }
    }
}

impl FromStr for AgentMethod {
    type Err = UnknownMethod;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Status" => Ok(Self::Status),
            "Unlock" => Ok(Self::Unlock),
            "Lock" => Ok(Self::Lock),
            "RegisterClient" => Ok(Self::RegisterClient),
            "RevokeClient" => Ok(Self::RevokeClient),
            "RequestGrant" => Ok(Self::RequestGrant),
            "RevokeGrant" => Ok(Self::RevokeGrant),
            "ExpireGrant" => Ok(Self::ExpireGrant),
            "ResolveReference" => Ok(Self::ResolveReference),
            "PrepareExec" => Ok(Self::PrepareExec),
            "ScanKnownValues" => Ok(Self::ScanKnownValues),
            "ListRuntimeSessions" => Ok(Self::ListRuntimeSessions),
            "ListPolicies" => Ok(Self::ListPolicies),
            "Reveal" => Ok(Self::Reveal),
            "Copy" => Ok(Self::Copy),
            "VerifyAudit" => Ok(Self::VerifyAudit),
            "ListAudit" => Ok(Self::ListAudit),
            "SubscribeStatus" => Ok(Self::SubscribeStatus),
            "CancelSubscription" => Ok(Self::CancelSubscription),
            "ClientHello" => Ok(Self::ClientHello),
            "ListSecrets" => Ok(Self::ListSecrets),
            "ListVersions" => Ok(Self::ListVersions),
            other => Err(UnknownMethod { method: other.to_owned() }),
        }
    }
}

/// Unknown v1 agent method name.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("unknown agent method: {method}")]
pub struct UnknownMethod {
    /// Method string found in the envelope.
    pub method: String,
}
