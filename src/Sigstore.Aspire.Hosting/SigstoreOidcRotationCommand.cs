namespace Aspire.Hosting.ApplicationModel;

/// <summary>
/// OIDC signing key rotation command using the TUF worker to create
/// generation N+1 with new OIDC material. Preserves generation
/// immutability and advances TUF trust_status coherently.
///
/// Phases: preflight → capture-old-token → write-signal → start-worker →
///         wait-worker → postconditions → restart-oidc → verify-new-token →
///         restart-clients → verify-fulcio → aggregate → complete
///
/// Recovery: worker handles interrupted generation advance deterministically.
/// Completion file enables exactly-once replay correlation.
/// </summary>
internal static class SigstoreOidcRotationCommand
{
    public static CommandOptions CreateOptions(SigstoreResource resource) =>
        new()
        {
            Description =
                "Rotates the OIDC signing key by creating generation N+1 " +
                "with a new RSA key pair, overlapping JWKS, and retained " +
                "historical private keys.",
            ConfirmationMessage =
                "This will generate a new OIDC signing key, advance the " +
                "trust generation, restart the OIDC issuer and all six " +
                "clients. Fulcio will NOT be restarted (it discovers new " +
                "keys via JWKS refresh). Proceed?",
            IsHighlighted = true,
            UpdateState = _ =>
                SigstoreOperationCommand.GetMutationCommandState(resource),
            Progress = new CommandProgressOptions
            {
                Title = "Rotate OIDC signing key",
                Message =
                    "Advancing trust, restarting OIDC once, and proving old/new " +
                    "token issuance through Fulcio.",
                HideCancelButton = true
            }
        };

    public static Task<ExecuteCommandResult> ExecuteAsync(
        SigstoreResource resource,
        ExecuteCommandContext context)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ArgumentNullException.ThrowIfNull(context);

        var runtime = new AspireSigstoreOperationRuntime(
            resource,
            context.Services);
        return new SigstoreOperationExecutor(
                resource,
                runtime,
                new SigstoreFileStateInspector(),
                context.Logger)
            .ExecuteRotateOidcSigningKeyAsync(context.CancellationToken);
    }
}
