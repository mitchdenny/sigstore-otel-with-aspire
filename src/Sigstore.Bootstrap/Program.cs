using Sigstore.Bootstrap;

var statePath =
    Environment.GetEnvironmentVariable("SIGSTORE_STATE_PATH")
    ?? throw new InvalidOperationException(
        "SIGSTORE_STATE_PATH must identify the Sigstore state directory.");

var result = SigstoreStateBootstrapper.EnsureInitialized(statePath);

Console.WriteLine(
    $"{result.Action} Sigstore trust state at {Path.GetFullPath(statePath)}.");
Console.WriteLine(
    $"Trust domain: {result.TrustDomain.TrustDomainId}");
Console.WriteLine(
    $"Active generation: {result.Generation.GenerationId}");
Console.WriteLine(
    $"Fulcio root SHA-256: {result.Generation.FulcioRootSha256}");
Console.WriteLine(
    $"CT log public key SHA-256: " +
    $"{result.Generation.CtLogPublicKeySha256}");
Console.WriteLine(
    $"Rekor public key SHA-256: " +
    $"{result.Generation.RekorPublicKeySha256}");
Console.WriteLine(
    $"TSA root SHA-256: {result.Generation.TsaRootSha256}");
Console.WriteLine(
    $"TSA leaf SHA-256: {result.Generation.TsaLeafSha256}");
Console.WriteLine(
    $"OIDC key ID: {result.Generation.OidcKeyId}");
