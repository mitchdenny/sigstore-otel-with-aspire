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

internal sealed record BootstrapResult(
    bool Created,
    BootstrapManifest Manifest);
