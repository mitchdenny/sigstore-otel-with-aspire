namespace Sigstore.Bootstrap;

internal sealed record BootstrapManifest(
    int SchemaVersion,
    DateTimeOffset CreatedAtUtc,
    string CtLogStateId,
    string RekorStateId,
    string FulcioRootSha256,
    string CtLogPublicKeySha256,
    string RekorPublicKeySha256,
    string TsaRootSha256,
    string TsaLeafSha256,
    string OidcKeyId);

internal enum BootstrapAction
{
    Created,
    Migrated,
    Recovered,
    Reused
}

internal sealed record BootstrapResult(
    BootstrapAction Action,
    TrustDomainManifest TrustDomain,
    GenerationManifest Generation);

internal sealed record TimestampAuthorityMaterialInfo(
    string RootSha256,
    string LeafSha256,
    string SignerPublicKeySha256,
    string CertificateChainSha256,
    bool HasRootPrivateKey,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc);

internal sealed record FulcioCaMaterialInfo(
    string RootSha256,
    string PublicKeySha256,
    string SubjectDistinguishedName,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc);

internal sealed record RekorShardMaterialInfo(
    string PublicKeySha256,
    string LogId,
    string ShardId);

/// <summary>
/// The identity of one certificate-transparency log shard's signer: the
/// SHA-256 fingerprint of its ECDSA P-256 SubjectPublicKeyInfo, which is
/// also the CT log ID that appears in embedded SCTs and in the TrustedRoot
/// <c>ctlogs</c> entry, plus the derived stable shard ID.
/// </summary>
internal sealed record CtLogShardMaterialInfo(
    string PublicKeySha256,
    string LogId,
    string ShardId);

/// <summary>
/// One certificate-transparency shard's least-privilege runtime projection:
/// its signer identity plus the validated identity of the complete Fulcio
/// root bundle the shard accepts. The bundle identity carries both the
/// SHA-256 of the exact bundle bytes and the ordered per-root fingerprints,
/// so the shard catalog can bind accepted trust durably and any added,
/// removed or reordered root is detectable.
/// </summary>
internal sealed record CtLogShardRuntimeInfo(
    string PublicKeySha256,
    string LogId,
    string ShardId,
    string AcceptedRootsSha256,
    IReadOnlyList<string> AcceptedRootFingerprints);

/// <summary>
/// The certificate-transparency configuration the running Fulcio is bound
/// to (<c>runtime/fulcio-ct</c>): the selector the single atomic selection
/// manifest names, plus the additive secondary shard key staged beside it
/// when a CT shard rotation is waiting for hosting to promote it.
/// </summary>
internal sealed record FulcioCtRuntimeProjectionInfo(
    string Selector,
    string Origin,
    string CtLogPublicKeySha256,
    string? StagedSelector,
    string? StagedOrigin,
    string? StagedCtLogPublicKeySha256,
    bool PromotionPending);

internal sealed record FulcioRuntimeProjectionInfo(
    string ActiveRootSha256,
    string ActivePublicKeySha256,
    string ActiveRootSubject,
    DateTimeOffset ActiveNotBeforeUtc,
    DateTimeOffset ActiveNotAfterUtc,
    string ActiveCtLogPublicKeySha256,
    string? StagedRootSha256,
    bool PromotionPending,
    string AcceptedRootsSha256,
    IReadOnlyList<string> AcceptedRootSha256);
