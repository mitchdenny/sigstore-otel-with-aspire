namespace Aspire.Hosting.ApplicationModel;

internal static class SigstoreCtLogShardRotationCommand
{
    public static CommandOptions CreateOptions(SigstoreResource resource) =>
        new()
        {
            Description =
                "Rotates the certificate-transparency log to a single " +
                "bounded secondary shard. Creates an isolated secondary " +
                "Tesseract shard with its own signer, origin, URL and " +
                "storage, proves it healthy and signing its own " +
                "checkpoint, publishes it additively through TUF so the " +
                "historical shard stays verifiable, converges all six " +
                "clients, proves the old shard still issues, and only " +
                "then moves Fulcio onto the new shard with exactly one " +
                "restart. The historical primary shard is never restarted " +
                "or mutated.",
            ConfirmationMessage =
                "Rotate the certificate-transparency log to a new bounded " +
                "secondary shard? The secondary shard will be created and " +
                "proven healthy, both certificate-transparency logs will " +
                "be published additively so existing certificates remain " +
                "verifiable, all six clients will converge, the old shard " +
                "will be proven to still issue, and only then will Fulcio " +
                "restart exactly once onto the new shard. The historical " +
                "primary shard will not be restarted or mutated, and " +
                "SigningConfig will not change. Proceed?",
            IsHighlighted = true,
            UpdateState = _ =>
                SigstoreOperationCommand.GetCtLogShardRotationCommandState(
                    resource),
            Progress = new CommandProgressOptions
            {
                Title = "Rotate CT log shard",
                Message =
                    "Preparing the secondary certificate-transparency " +
                    "shard, publishing additive trust, converging " +
                    "clients, and moving Fulcio onto the new shard.",
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
            .ExecuteRotateCtLogShardAsync(context.CancellationToken);
    }
}
