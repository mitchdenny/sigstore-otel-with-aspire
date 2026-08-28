namespace Aspire.Hosting.ApplicationModel;

internal static class SigstoreFulcioRotationCommand
{
    public static CommandOptions CreateOptions(SigstoreResource resource) =>
        new()
        {
            Description =
                "Rotates the Fulcio file CA through additive TUF trust, " +
                "converges all six clients, restarts Tesseract with the full " +
                "root history, then activates the new Fulcio signer.",
            ConfirmationMessage =
                "Rotate the Fulcio CA? The old and new roots will be published " +
                "additively, all six clients will converge, Tesseract will " +
                "restart and prove the old CA first, and only then will Fulcio " +
                "restart exactly once on the new CA. Other services and CT log " +
                "identity remain unchanged. Proceed?",
            IsHighlighted = true,
            UpdateState = _ =>
                SigstoreOperationCommand.GetFulcioRotationCommandState(
                    resource),
            Progress = new CommandProgressOptions
            {
                Title = "Rotate Fulcio CA",
                Message =
                    "Publishing additive trust, proving Tesseract overlap, " +
                    "and activating the new Fulcio CA.",
                HideCancelButton = true
            }
        };

    public static Task<ExecuteCommandResult> ExecuteAsync(
        SigstoreResource resource,
        ExecuteCommandContext context)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ArgumentNullException.ThrowIfNull(context);

        return new SigstoreOperationExecutor(
                resource,
                new AspireSigstoreOperationRuntime(
                    resource,
                    context.Services),
                new SigstoreFileStateInspector(),
                context.Logger)
            .ExecuteRotateFulcioCaAsync(context.CancellationToken);
    }
}
