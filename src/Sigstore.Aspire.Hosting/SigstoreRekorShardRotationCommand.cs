namespace Aspire.Hosting.ApplicationModel;

internal static class SigstoreRekorShardRotationCommand
{
    public static CommandOptions CreateOptions(SigstoreResource resource) =>
        new()
        {
            Description =
                "Rotates the Rekor transparency log to a single bounded " +
                "secondary shard. Prepares an isolated secondary signer, " +
                "proves it healthy behind the gateway, publishes the new " +
                "log additively through TUF, converges all six clients, " +
                "and only then routes new entries to the secondary shard. " +
                "The primary Rekor server is never restarted.",
            ConfirmationMessage =
                "Rotate the Rekor transparency log to a new bounded " +
                "secondary shard? The secondary shard will be started and " +
                "proven healthy, its log will be published additively so " +
                "the original shard remains verifiable, all six clients " +
                "will converge, and only then will new entries route to " +
                "the secondary shard. The primary Rekor server will not be " +
                "restarted or mutated. Proceed?",
            IsHighlighted = true,
            UpdateState = _ =>
                SigstoreOperationCommand.GetRekorShardRotationCommandState(
                    resource),
            Progress = new CommandProgressOptions
            {
                Title = "Rotate Rekor shard",
                Message =
                    "Preparing the secondary Rekor shard, publishing " +
                    "additive trust, converging clients, and activating " +
                    "the new shard.",
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
            .ExecuteRotateRekorShardAsync(context.CancellationToken);
    }
}
