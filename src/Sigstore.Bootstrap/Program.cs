using Sigstore.Bootstrap;

var statePath =
    Environment.GetEnvironmentVariable("SIGSTORE_STATE_PATH")
    ?? throw new InvalidOperationException(
        "SIGSTORE_STATE_PATH must identify the Sigstore state directory.");

var result = SigstoreStateBootstrapper.EnsureInitialized(statePath);
var action = result.Created ? "Created" : "Reused";

Console.WriteLine(
    $"{action} Sigstore bootstrap state at {Path.GetFullPath(statePath)}.");
Console.WriteLine(
    $"Fulcio root SHA-256: {result.Manifest.FulcioRootSha256}");
Console.WriteLine(
    $"CT log public key SHA-256: {result.Manifest.CtLogPublicKeySha256}");
Console.WriteLine(
    $"Rekor public key SHA-256: {result.Manifest.RekorPublicKeySha256}");
Console.WriteLine(
    $"TSA root SHA-256: {result.Manifest.TsaRootSha256}");
Console.WriteLine(
    $"TSA leaf SHA-256: {result.Manifest.TsaLeafSha256}");
Console.WriteLine(
    $"OIDC key ID: {result.Manifest.OidcKeyId}");
