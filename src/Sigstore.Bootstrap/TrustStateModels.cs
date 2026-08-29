namespace Sigstore.Bootstrap;

internal sealed record TrustDomainManifest(
    int SchemaVersion,
    string TrustDomainId,
    DateTimeOffset CreatedAtUtc,
    string CtLogStateId,
    string RekorStateId);

internal sealed record GenerationManifest(
    int SchemaVersion,
    int Generation,
    string GenerationId,
    string TrustDomainId,
    DateTimeOffset CreatedAtUtc,
    int SourceSchemaVersion,
    string? SourceManifestSha256,
    string FulcioRootSha256,
    string CtLogPublicKeySha256,
    string RekorPublicKeySha256,
    string TsaRootSha256,
    string TsaLeafSha256,
    string OidcKeyId,
    string? OidcRotationOperationId,
    int OidcPriorGeneration,
    string? OidcPriorGenerationId,
    string? OidcPriorKeyId,
    DateTimeOffset? OidcOverlapExpiresAtUtc,
    IReadOnlyList<string>? OidcRetainedPrivateKeyPaths,
    string? TsaRotationOperationId,
    int TsaPriorGeneration,
    string? TsaPriorGenerationId,
    string? TsaPriorRootSha256,
    string? TsaPriorLeafSha256,
    string? FulcioRotationOperationId,
    int FulcioPriorGeneration,
    string? FulcioPriorGenerationId,
    string? FulcioPriorRootSha256,
    string? RekorRotationOperationId,
    int RekorPriorGeneration,
    string? RekorPriorGenerationId,
    string? RekorPriorPublicKeySha256,
    string? RekorPriorShardId,
    string? RekorPriorBaseUrl,
    string? RekorShardId,
    string? RekorBaseUrl,
    SortedDictionary<string, string> Files);

internal sealed record GenerationReference(
    int Generation,
    string GenerationId,
    string ManifestSha256);

internal sealed record TrustTransitionJournal(
    int SchemaVersion,
    string TransitionId,
    string Operation,
    string Status,
    string LastCheckpoint,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    GenerationReference? PriorGeneration,
    GenerationReference Candidate,
    string TrustDomainManifestSha256,
    string? LegacyManifestSha256,
    TrustDomainManifest TrustDomain,
    GenerationManifest CandidateManifest,
    string? Failure);

internal enum TrustTransitionCheckpoint
{
    JournalStaged,
    CandidateDirectoryCreated,
    PrivateMaterialStaged,
    PublicMaterialStaged,
    GenerationManifestStaged,
    TrustDomainPrepared,
    TrustDomainCommitted,
    GenerationCommitted,
    ActiveLinkPrepared,
    ActiveGenerationSwitched,
    TransitionCommitted,
    LegacyManifestArchived,
    TransitionFinalized
}

internal sealed record TrustStateOperationOptions(
    TimeSpan LockTimeout,
    Action<TrustTransitionCheckpoint>? Checkpoint = null)
{
    public static TrustStateOperationOptions Default { get; } =
        new(TimeSpan.FromSeconds(30));
}

internal sealed class TrustTransitionInterruptedException(string message)
    : Exception(message);
