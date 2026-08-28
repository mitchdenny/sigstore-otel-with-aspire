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
