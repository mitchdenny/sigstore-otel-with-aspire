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
