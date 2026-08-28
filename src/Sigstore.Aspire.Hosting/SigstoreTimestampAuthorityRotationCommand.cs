namespace Aspire.Hosting.ApplicationModel;

internal static class SigstoreTimestampAuthorityRotationCommand
{
    public static CommandOptions CreateOptions(SigstoreResource resource) =>
        new()
        {
            Description =
                "Rotates the RFC3161 timestamp authority through an additive " +
                "TrustedRoot generation, converges all six clients, then " +
                "restarts only the timestamp service.",
            ConfirmationMessage =
                "Rotate the timestamp authority? A new TSA chain will be " +
                "published additively, all six clients will restart, and only " +
                "then will the timestamp service restart exactly once. Other " +
                "Sigstore services and routing remain unchanged. Proceed?",
            IsHighlighted = true,
            UpdateState = _ =>
                SigstoreOperationCommand
                    .GetTimestampAuthorityRotationCommandState(resource),
            Progress = new CommandProgressOptions
            {
                Title = "Rotate timestamp authority",
                Message =
                    "Publishing additive TSA trust, converging clients, and " +
                    "activating the new RFC3161 signer.",
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
            .ExecuteRotateTimestampAuthorityAsync(
                context.CancellationToken);
    }
}
