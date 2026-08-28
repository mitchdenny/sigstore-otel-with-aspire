using System.Globalization;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Sigstore.Bootstrap;

namespace Aspire.Hosting.ApplicationModel;

internal static class SigstoreOperationCommand
{
    public const string RefreshTufCommand = "refresh-tuf";
    public const string RotateTufRootCommand = "rotate-tuf-root";
    public const string RestartClientsCommand = "restart-clients";
    public const string PublishTrustedRootCommand = "publish-trusted-root";
    public const string RotateOidcSigningKeyCommand = "rotate-oidc-signing-key";

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        };

    public static CommandOptions CreateRefreshTufOptions(
        SigstoreResource resource) =>
        new()
        {
            Description =
                "Refresh only signed TUF snapshot and timestamp metadata while " +
                "the current trust generation and TUF server remain unchanged.",
            ConfirmationMessage =
                "Refresh TUF snapshot and timestamp metadata? Root, targets, " +
                "trusted-root content, signing configuration, and the running " +
                "TUF server must remain unchanged.",
            IconName = "ArrowSync",
            IconVariant = IconVariant.Regular,
            UpdateState = _ => GetMutationCommandState(resource),
            Progress = new CommandProgressOptions
            {
                Title = "Refresh TUF metadata",
                Message =
                    "Refreshing and validating the signed TUF repository.",
                HideCancelButton = true
            }
        };

    public static CommandOptions CreateRotateTufRootOptions(
        SigstoreResource resource) =>
        new()
        {
            Description =
                "Rotate the TUF root signing key. Generates root N+1 signed " +
                "by both old and new keys, then updates snapshot and timestamp.",
            ConfirmationMessage =
                "Rotate the TUF root key? A new root version will be " +
                "published with fresh signing keys. Bootstrap root, targets " +
                "content, and trust generation remain unchanged.",
            IconName = "KeyMultiple",
            IconVariant = IconVariant.Regular,
            UpdateState = _ => GetMutationCommandState(resource),
            Progress = new CommandProgressOptions
            {
                Title = "Rotate TUF root key",
                Message =
                    "Generating root N+1 with new key and validating the " +
                    "full versioned root chain.",
                HideCancelButton = true
            }
        };

    public static CommandOptions CreateRestartClientsOptions(
        SigstoreResource resource) =>
        new()
        {
            Description =
                "Restart all six language clients in deterministic order and " +
                "wait for healthy, current trust status from every client.",
            ConfirmationMessage =
                "Restart all six Sigstore client containers? Sigstore services " +
                "and committed trust state will not be restarted or changed.",
            IconName = "ArrowCounterclockwise",
            IconVariant = IconVariant.Regular,
            UpdateState = _ => GetMutationCommandState(resource),
            Progress = new CommandProgressOptions
            {
                Title = "Restart Sigstore clients",
                Message =
                    "Restarting clients and waiting for verified trust status.",
                HideCancelButton = true
            }
        };

    public static Task<ExecuteCommandResult> ExecuteRefreshTufAsync(
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
            .ExecuteRefreshTufAsync(context.CancellationToken);
    }

    public static Task<ExecuteCommandResult> ExecuteRotateTufRootAsync(
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
            .ExecuteRotateTufRootAsync(context.CancellationToken);
    }

    public static Task<ExecuteCommandResult> ExecuteRestartClientsAsync(
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
            .ExecuteRestartClientsAsync(context.CancellationToken);
    }

    public static CommandOptions CreatePublishTrustedRootOptions(
        SigstoreResource resource) =>
        new()
        {
            Description =
                "Publish an additive trusted-root update through TUF. Advances " +
                "the trust generation with standby verification material, " +
                "restarts all clients, and waits for convergence.",
            ConfirmationMessage =
                "Publish an additive trusted-root update? This will advance " +
                "the trust generation, update TUF targets, and restart all " +
                "six clients. No signer is activated. Historical verification " +
                "material is preserved.",
            IconName = "ShieldCheckmark",
            IconVariant = IconVariant.Regular,
            UpdateState = _ => GetMutationCommandState(resource),
            Progress = new CommandProgressOptions
            {
                Title = "Publish trusted root",
                Message =
                    "Advancing trust generation and publishing additive " +
                    "verification material through TUF.",
                HideCancelButton = true
            }
        };

    public static Task<ExecuteCommandResult> ExecutePublishTrustedRootAsync(
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
            .ExecutePublishTrustedRootAsync(context.CancellationToken);
    }

    internal static ResourceCommandState GetMutationCommandState(
        SigstoreResource resource)
    {
        var presentation = resource.GetPresentation();
        return presentation.Operation is null
            && presentation.RuntimeHealth.State == "Healthy"
                ? ResourceCommandState.Enabled
                : ResourceCommandState.Disabled;
    }

    internal static ExecuteCommandResult CreateResult(
        SigstoreOperationResult result)
    {
        var json = JsonSerializer.Serialize(result, JsonOptions);
        return new ExecuteCommandResult
        {
            Success = result.Success,
            Message = result.Message,
            Data = new CommandResultData
            {
                Value = json,
                Format = CommandResultFormat.Json,
                DisplayImmediately = true
            }
        };
    }
}

internal sealed class SigstoreOperationExecutor(
    SigstoreResource resource,
    ISigstoreOperationRuntime runtime,
    ISigstoreStateInspector stateInspector,
    ILogger logger)
{
    private static readonly TimeSpan WorkerTimeout =
        TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ClientTimeout =
        TimeSpan.FromMinutes(3);
    private static readonly TimeSpan AggregateTimeout =
        TimeSpan.FromMinutes(2);

    public async Task<ExecuteCommandResult> ExecuteRefreshTufAsync(
        CancellationToken requestCancellationToken)
    {
        requestCancellationToken.ThrowIfCancellationRequested();
        if (!resource.TryBeginOperation(
                SigstoreOperationCommand.RefreshTufCommand,
                "Refreshing TUF",
                out var lease,
                out var active))
        {
            return CreateContentionResult(
                SigstoreOperationCommand.RefreshTufCommand,
                active!);
        }

        var execution = new OperationExecution(
            resource,
            runtime,
            logger,
            lease!,
            total: 6);
        try
        {
            return await ExecuteRefreshTufCoreAsync(
                execution,
                requestCancellationToken);
        }
        catch (Exception exception)
            when (IsExpectedOperationFailure(exception))
        {
            execution.AddError(
                execution.Phase,
                resource.Name,
                null,
                exception.Message);
            return execution.Failure(
                $"{SigstoreOperationCommand.RefreshTufCommand} failed during " +
                $"{execution.Phase}.");
        }
        finally
        {
            lease!.Dispose();
            await runtime.PublishParentStateAsync(resource);
        }
    }

    public async Task<ExecuteCommandResult> ExecuteRotateTufRootAsync(
        CancellationToken requestCancellationToken)
    {
        requestCancellationToken.ThrowIfCancellationRequested();
        if (!resource.TryBeginOperation(
                SigstoreOperationCommand.RotateTufRootCommand,
                "Rotating TUF Root",
                out var lease,
                out var active))
        {
            return CreateContentionResult(
                SigstoreOperationCommand.RotateTufRootCommand,
                active!);
        }

        var execution = new OperationExecution(
            resource,
            runtime,
            logger,
            lease!,
            total: 7);
        try
        {
            return await ExecuteRotateTufRootCoreAsync(
                execution,
                requestCancellationToken);
        }
        catch (Exception exception)
            when (IsExpectedOperationFailure(exception))
        {
            execution.AddError(
                execution.Phase,
                resource.Name,
                null,
                exception.Message);
            return execution.Failure(
                $"{SigstoreOperationCommand.RotateTufRootCommand} failed " +
                $"during {execution.Phase}.");
        }
        finally
        {
            lease!.Dispose();
            await runtime.PublishParentStateAsync(resource);
        }
    }

    public async Task<ExecuteCommandResult> ExecuteRestartClientsAsync(
        CancellationToken requestCancellationToken)
    {
        requestCancellationToken.ThrowIfCancellationRequested();
        if (!resource.TryBeginOperation(
                SigstoreOperationCommand.RestartClientsCommand,
                "Restarting Clients",
                out var lease,
                out var active))
        {
            return CreateContentionResult(
                SigstoreOperationCommand.RestartClientsCommand,
                active!);
        }

        var execution = new OperationExecution(
            resource,
            runtime,
            logger,
            lease!,
            total: 9);
        try
        {
            return await ExecuteRestartClientsCoreAsync(
                execution,
                requestCancellationToken);
        }
        catch (Exception exception)
            when (IsExpectedOperationFailure(exception))
        {
            execution.AddError(
                execution.Phase,
                resource.Name,
                null,
                exception.Message);
            return execution.Failure(
                $"{SigstoreOperationCommand.RestartClientsCommand} failed " +
                $"during {execution.Phase}.");
        }
        finally
        {
            lease!.Dispose();
            await runtime.PublishParentStateAsync(resource);
        }
    }

    public async Task<ExecuteCommandResult> ExecutePublishTrustedRootAsync(
        CancellationToken requestCancellationToken)
    {
        requestCancellationToken.ThrowIfCancellationRequested();
        if (!resource.TryBeginOperation(
                SigstoreOperationCommand.PublishTrustedRootCommand,
                "Publishing Trusted Root",
                out var lease,
                out var active))
        {
            return CreateContentionResult(
                SigstoreOperationCommand.PublishTrustedRootCommand,
                active!);
        }

        var execution = new OperationExecution(
            resource,
            runtime,
            logger,
            lease!,
            total: 12);
        try
        {
            return await ExecutePublishTrustedRootCoreAsync(
                execution,
                requestCancellationToken);
        }
        catch (Exception exception)
            when (IsExpectedOperationFailure(exception))
        {
            execution.AddError(
                execution.Phase,
                resource.Name,
                null,
                exception.Message);
            return execution.Failure(
                $"{SigstoreOperationCommand.PublishTrustedRootCommand} failed " +
                $"during {execution.Phase}.");
        }
        finally
        {
            lease!.Dispose();
            await runtime.PublishParentStateAsync(resource);
        }
    }

    public async Task<ExecuteCommandResult> ExecuteRotateOidcSigningKeyAsync(
        CancellationToken requestCancellationToken)
    {
        requestCancellationToken.ThrowIfCancellationRequested();
        if (!resource.TryBeginOperation(
                SigstoreOperationCommand.RotateOidcSigningKeyCommand,
                "Rotating OIDC signing key",
                out var lease,
                out var active))
        {
            return CreateContentionResult(
                SigstoreOperationCommand.RotateOidcSigningKeyCommand,
                active!);
        }

        var execution = new OperationExecution(
            resource,
            runtime,
            logger,
            lease!,
            total: 14);
        try
        {
            return await ExecuteRotateOidcSigningKeyCoreAsync(
                execution,
                requestCancellationToken);
        }
        catch (Exception exception)
            when (IsExpectedOperationFailure(exception))
        {
            execution.AddError(
                execution.Phase,
                resource.Name,
                null,
                exception.Message);
            return execution.Failure(
                $"{SigstoreOperationCommand.RotateOidcSigningKeyCommand} failed " +
                $"during {execution.Phase}.");
        }
        finally
        {
            lease!.Dispose();
            await runtime.PublishParentStateAsync(resource);
        }
    }

    private async Task<ExecuteCommandResult> ExecuteRotateOidcSigningKeyCoreAsync(
        OperationExecution execution,
        CancellationToken requestCancellationToken)
    {
        // Phase 0: Preflight
        await execution.ReportAsync(
            "preflight", 0,
            "Validating current trust, OIDC, and Fulcio state for OIDC key rotation.");

        SigstoreOperationSnapshot before;
        SigstoreResourceInstanceSnapshot workerBefore;
        SigstoreResourceInstanceSnapshot oidcBefore;
        SigstoreResourceInstanceSnapshot fulcioBefore;
        string? oldTokenJwt = null;
        string? oldTokenKid = null;
        string? beforeOidcKeyId = null;
        string? afterOidcKeyId = null;

        ExecuteCommandResult workerStart;
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-rotate-oidc-preflight"))
        {
            requestCancellationToken.ThrowIfCancellationRequested();
            before = await CaptureAsync(requestCancellationToken);
            execution.Before = before;
            beforeOidcKeyId = ReadOidcKeyIdFromManifest(resource.StatePath);

            workerBefore = runtime.GetRequiredSnapshot(
                resource.Components.TufBootstrap.Resource);
            if (!execution.Check(
                    "worker-ready",
                    IsSuccessfulTerminal(workerBefore),
                    "a completed one-shot with exit code 0",
                    Describe(workerBefore),
                    "preflight",
                    workerBefore.Resource))
            {
                return execution.Failure(
                    "The TUF worker is not ready for OIDC rotation.");
            }

            oidcBefore = runtime.GetRequiredSnapshot(
                resource.Components.Oidc.Resource);
            if (!execution.Check(
                    "oidc-running",
                    IsRunningHealthy(oidcBefore) && HasContainerIdentity(oidcBefore),
                    "Running/Healthy with container identity",
                    Describe(oidcBefore),
                    "preflight",
                    oidcBefore.Resource))
            {
                return execution.Failure("OIDC issuer is not healthy for rotation.");
            }

            fulcioBefore = runtime.GetRequiredSnapshot(
                resource.Components.Fulcio.Resource);
            if (!execution.Check(
                    "fulcio-running",
                    IsRunningHealthy(fulcioBefore) && HasContainerIdentity(fulcioBefore),
                    "Running/Healthy with container identity",
                    Describe(fulcioBefore),
                    "preflight",
                    fulcioBefore.Resource))
            {
                return execution.Failure("Fulcio is not healthy for rotation.");
            }

            // Phase 1: Capture old-key token.
            await execution.ReportAsync(
                "capture-old-token", 1,
                "Capturing a token signed by the current OIDC key for overlap proof.");
            (oldTokenJwt, oldTokenKid) = await CaptureOidcTokenAsync(
                requestCancellationToken);
            if (oldTokenJwt == null || oldTokenKid == null)
            {
                execution.AddError(
                    "capture-old-token", resource.Components.Oidc.Resource.Name,
                    null, "Could not obtain pre-rotation OIDC token.");
                return execution.Failure("Failed to capture pre-rotation OIDC token.");
            }
            execution.Check(
                "old-token-kid-matches-generation",
                oldTokenKid == beforeOidcKeyId,
                beforeOidcKeyId ?? "null",
                oldTokenKid,
                "capture-old-token",
                resource.Components.Oidc.Resource.Name);

            // Phase 2: Write signal file.
            await execution.ReportAsync(
                "write-signal", 2,
                "Writing rotate-oidc-signing-key.request signal file.");
            var operationId = Guid.NewGuid().ToString("N");
            var signalPath = Path.Combine(
                resource.StatePath,
                "rotate-oidc-signing-key.request");
            var requestContent = System.Text.Json.JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                operationId,
                trustDomainId = before.Tuf.Trust.TrustDomainId
            });
            try
            {
                await using var fs = new FileStream(
                    signalPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                var bytes = System.Text.Encoding.UTF8.GetBytes(requestContent);
                await fs.WriteAsync(bytes, requestCancellationToken);
                await fs.FlushAsync(requestCancellationToken);
            }
            catch (IOException ex) when (ex.HResult == unchecked((int)0x80070050)
                || File.Exists(signalPath))
            {
                execution.AddError(execution.Phase, resource.Name, null,
                    "A rotate-oidc-signing-key.request file already exists.");
                return execution.Failure(
                    "Cannot issue OIDC rotation: surviving request file exists.");
            }

            // Phase 3: Start TUF worker.
            await execution.ReportAsync(
                "start-worker", 3,
                "Starting TUF one-shot to create generation N+1 with new OIDC key.");
            using var workerCritical = new CancellationTokenSource(WorkerTimeout);
            workerStart = await runtime.ExecuteCommandAsync(
                resource.Components.TufBootstrap.Resource,
                KnownResourceCommands.StartCommand,
                workerCritical.Token);
        }

        if (!workerStart.Success)
        {
            execution.AddError("start-worker",
                resource.Components.TufBootstrap.Resource.Name, null,
                workerStart.Message ?? "Aspire rejected TUF worker start.");
            return execution.Failure("TUF worker could not be started for OIDC rotation.");
        }

        // Phase 4: Wait for worker.
        await execution.ReportAsync(
            "wait-worker", 4,
            "Waiting for OIDC rotation worker to complete generation advance.");
        SigstoreResourceInstanceSnapshot workerAfter;
        using (var workerWait = new CancellationTokenSource(WorkerTimeout))
        {
            try
            {
                workerAfter = await runtime.WaitForSnapshotAsync(
                    resource.Components.TufBootstrap.Resource,
                    snapshot => IsNewInstance(workerBefore, snapshot)
                        && IsTerminal(snapshot),
                    WorkerTimeout,
                    workerWait.Token);
            }
            catch (OperationCanceledException exception)
            {
                execution.AddError("wait-worker",
                    resource.Components.TufBootstrap.Resource.Name, null,
                    exception.Message);
                return execution.Failure("OIDC rotation worker timed out.");
            }
        }
        execution.Resources.Add(CreateLifecycleResult(
            resource.Components.TufBootstrap.Resource.Name,
            KnownResourceCommands.StartCommand, workerBefore, workerAfter, null));
        if (!IsSuccessfulTerminal(workerAfter))
        {
            execution.AddError("wait-worker", workerAfter.Resource, null,
                $"Worker completed as {Describe(workerAfter)}.");
            return execution.Failure("OIDC rotation worker failed.");
        }

        // Phase 5: Postconditions.
        await execution.ReportAsync(
            "postconditions", 5,
            "Validating generation advance and new OIDC key ID.");
        SigstoreOperationSnapshot after;
        using (stateInspector.AcquireLock(resource.StatePath,
            "dashboard-rotate-oidc-postconditions"))
        {
            using var postToken = new CancellationTokenSource(WorkerTimeout);
            after = await CaptureAsync(postToken.Token);
            execution.After = after;
            afterOidcKeyId = ReadOidcKeyIdFromManifest(resource.StatePath);
        }
        execution.Check("generation-advanced",
            after.Tuf.Trust.Generation == before.Tuf.Trust.Generation + 1
                && after.Tuf.Trust.GenerationId != before.Tuf.Trust.GenerationId,
            $"generation {before.Tuf.Trust.Generation + 1}",
            $"generation {after.Tuf.Trust.Generation}",
            "postconditions", "tuf-bootstrap");
        execution.Check("oidc-key-changed",
            afterOidcKeyId != beforeOidcKeyId
                && !string.IsNullOrEmpty(afterOidcKeyId),
            $"new kid != {beforeOidcKeyId}",
            afterOidcKeyId ?? "null",
            "postconditions", "tuf-bootstrap");
        CheckEqual(execution, "trust-domain-unchanged",
            before.Tuf.Trust.TrustDomainId, after.Tuf.Trust.TrustDomainId);
        CheckEqual(execution, "trusted-root-unchanged",
            before.Tuf.Trust.TrustedRootSha256, after.Tuf.Trust.TrustedRootSha256);
        CheckEqual(execution, "signing-config-unchanged",
            before.Tuf.Trust.SigningConfigSha256, after.Tuf.Trust.SigningConfigSha256);
        if (execution.HasFailures)
            return execution.Failure("OIDC rotation postconditions failed.");

        // Phase 6: Restart OIDC.
        await execution.ReportAsync("restart-oidc", 6,
            "Restarting OIDC issuer to activate new signing key.");
        var oidcRestart = await runtime.ExecuteCommandAsync(
            resource.Components.Oidc.Resource,
            KnownResourceCommands.RestartCommand,
            requestCancellationToken);
        if (!oidcRestart.Success)
        {
            execution.AddError("restart-oidc",
                resource.Components.Oidc.Resource.Name, null,
                oidcRestart.Message ?? "OIDC restart rejected.");
            return execution.Failure("Could not restart OIDC issuer.");
        }
        SigstoreResourceInstanceSnapshot oidcAfter;
        using (var oidcWait = new CancellationTokenSource(ClientTimeout))
        {
            try
            {
                oidcAfter = await runtime.WaitForSnapshotAsync(
                    resource.Components.Oidc.Resource,
                    snapshot => IsNewInstance(oidcBefore, snapshot)
                        && IsRunningHealthy(snapshot),
                    ClientTimeout, oidcWait.Token);
            }
            catch (OperationCanceledException ex)
            {
                execution.AddError("restart-oidc",
                    resource.Components.Oidc.Resource.Name, null, ex.Message);
                return execution.Failure("OIDC did not become healthy after restart.");
            }
        }
        execution.Resources.Add(CreateLifecycleResult(
            resource.Components.Oidc.Resource.Name,
            KnownResourceCommands.RestartCommand, oidcBefore, oidcAfter, null));
        execution.Check("oidc-new-identity",
            IsNewInstance(oidcBefore, oidcAfter),
            "new container identity", oidcAfter.ContainerId ?? "missing",
            "restart-oidc", resource.Components.Oidc.Resource.Name);

        // Phase 7: Verify new token.
        await execution.ReportAsync("verify-new-token", 7,
            "Verifying new token uses rotated key.");
        var (newTokenJwt, newTokenKid) = await CaptureOidcTokenAsync(
            requestCancellationToken);
        if (newTokenJwt == null || newTokenKid == null)
        {
            execution.AddError("verify-new-token",
                resource.Components.Oidc.Resource.Name, null,
                "Could not obtain post-rotation token.");
            return execution.Failure("Failed to capture post-rotation token.");
        }
        execution.Check("new-token-uses-new-kid",
            newTokenKid == afterOidcKeyId,
            afterOidcKeyId ?? "null", newTokenKid,
            "verify-new-token", resource.Components.Oidc.Resource.Name);

        // Phase 8: Verify Fulcio NOT restarted.
        await execution.ReportAsync("verify-fulcio-stable", 8,
            "Confirming Fulcio was not restarted.");
        var fulcioAfterRotation = runtime.GetRequiredSnapshot(
            resource.Components.Fulcio.Resource);
        execution.Check("fulcio-not-restarted",
            SameInstance(fulcioBefore, fulcioAfterRotation)
                && IsRunningHealthy(fulcioAfterRotation),
            $"same identity {fulcioBefore.ContainerId}",
            fulcioAfterRotation.ContainerId ?? "different",
            "verify-fulcio-stable", resource.Components.Fulcio.Resource.Name);

        // Phase 9: Prove Fulcio issuance with old + new tokens.
        await execution.ReportAsync("prove-fulcio-issuance", 9,
            "Proving Fulcio accepts both old-key and new-key tokens.");
        var oldAccepted = await ProveFulcioCertIssuanceAsync(
            oldTokenJwt, requestCancellationToken);
        execution.Check("fulcio-accepts-old-token", oldAccepted,
            "issued", oldAccepted ? "issued" : "rejected",
            "prove-fulcio-issuance", resource.Components.Fulcio.Resource.Name);
        var newAccepted = await ProveFulcioCertIssuanceAsync(
            newTokenJwt, requestCancellationToken);
        execution.Check("fulcio-accepts-new-token", newAccepted,
            "issued", newAccepted ? "issued" : "rejected",
            "prove-fulcio-issuance", resource.Components.Fulcio.Resource.Name);
        if (execution.HasFailures)
            return execution.Failure("Fulcio issuance proof failed.");

        // Phase 10: Restart clients.
        await execution.ReportAsync("restart-clients", 10,
            "Restarting all six clients for trust generation convergence.");
        var clients = resource.GetRegistrations().Clients
            .OrderBy(c => c.Resource.Name, StringComparer.Ordinal).ToArray();
        if (!execution.Check("six-clients-registered",
                clients.Length == 6, "6",
                clients.Length.ToString(CultureInfo.InvariantCulture),
                "restart-clients", resource.Name))
            return execution.Failure("Not exactly six clients.");

        using var clientCritical = new CancellationTokenSource(
            TimeSpan.FromMinutes(20));
        foreach (var client in clients)
        {
            var clientBefore = runtime.GetRequiredSnapshot(client.Resource);
            if (!execution.Check($"{client.Resource.Name}-ready",
                    IsRunningHealthy(clientBefore) && HasContainerIdentity(clientBefore),
                    "Running/Healthy", Describe(clientBefore),
                    "restart-client", client.Resource.Name))
                return execution.Failure($"{client.Resource.Name} not ready.");

            var restart = await runtime.ExecuteCommandAsync(
                client.Resource, KnownResourceCommands.RestartCommand,
                clientCritical.Token);
            if (!restart.Success)
            {
                execution.AddError("restart-client", client.Resource.Name, null,
                    restart.Message ?? "Restart rejected.");
                return execution.Failure($"{client.Resource.Name} restart failed.");
            }

            SigstoreResourceInstanceSnapshot clientAfter;
            try
            {
                clientAfter = await runtime.WaitForSnapshotAsync(
                    client.Resource,
                    snapshot => IsNewInstance(clientBefore, snapshot)
                        && IsRunningHealthy(snapshot),
                    ClientTimeout, clientCritical.Token);
            }
            catch (OperationCanceledException ex)
            {
                execution.AddError("wait-client", client.Resource.Name, null,
                    ex.Message);
                return execution.Failure($"{client.Resource.Name} not healthy.");
            }

            var trustStatus = await runtime.ReadClientStatusAsync(
                client, clientCritical.Token);
            if (!execution.Check($"{client.Resource.Name}-trust-status",
                    MatchesDisk(after.Tuf.Trust, trustStatus),
                    DescribeTrust(after.Tuf.Trust), DescribeTrust(trustStatus),
                    "wait-client", client.Resource.Name))
                return execution.Failure($"{client.Resource.Name} stale trust.");

            execution.Resources.Add(CreateLifecycleResult(
                client.Resource.Name, KnownResourceCommands.RestartCommand,
                clientBefore, clientAfter, trustStatus));
        }

        // Phase 11: Aggregate.
        await execution.ReportAsync("aggregate-status", 11,
            "Waiting for aggregate health.");
        await runtime.WaitForAggregateHealthyAsync(
            AggregateTimeout, clientCritical.Token);
        var aggregate = await runtime.CollectStatusAsync(clientCritical.Token);
        execution.Check("aggregate-ready",
            aggregate.Ready && aggregate.Clients.Count == clients.Length,
            $"ready, {clients.Length} clients",
            aggregate.Reason ?? $"ready={aggregate.Ready}",
            "aggregate-status", resource.Name);

        // Phase 12: Final Fulcio check.
        await execution.ReportAsync("final-verification", 12,
            "Final Fulcio identity verification.");
        var fulcioFinal = runtime.GetRequiredSnapshot(
            resource.Components.Fulcio.Resource);
        execution.Check("fulcio-final-identity",
            SameInstance(fulcioBefore, fulcioFinal) && IsRunningHealthy(fulcioFinal),
            $"same {fulcioBefore.ContainerId}",
            fulcioFinal.ContainerId ?? "different",
            "final-verification", resource.Components.Fulcio.Resource.Name);

        if (execution.HasFailures)
            return execution.Failure("OIDC rotation convergence checks failed.");

        // Phase 13: Success.
        await execution.ReportAsync("complete", 13,
            "OIDC signing key rotated successfully.");
        return execution.Success(
            $"OIDC signing key rotated: {beforeOidcKeyId} → " +
            $"{afterOidcKeyId} (gen " +
            $"{before.Tuf.Trust.Generation} → {after.Tuf.Trust.Generation}). " +
            $"Fulcio identity unchanged ({fulcioBefore.ContainerId}).");
    }

    private async Task<(string? jwt, string? kid)> CaptureOidcTokenAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
            using var httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            var jwt = await httpClient.GetStringAsync(
                $"{SigstoreDefaults.ExpectedIssuer}/token", cancellationToken);
            if (string.IsNullOrWhiteSpace(jwt)) return (null, null);
            var kid = ExtractKidFromJwt(jwt);
            return (jwt, kid);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to capture OIDC token.");
            return (null, null);
        }
    }

    private async Task<bool> ProveFulcioCertIssuanceAsync(
        string oidcToken,
        CancellationToken cancellationToken)
    {
        try
        {
            using var httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue(
                    "Bearer", oidcToken);
            using var ecdsa = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var publicKeyDer = ecdsa.ExportSubjectPublicKeyInfo();
            var body = new
            {
                publicKeyRequest = new
                {
                    publicKey = new
                    {
                        algorithm = "ECDSA",
                        content = Convert.ToBase64String(publicKeyDer)
                    },
                    proofOfPossession = Convert.ToBase64String(
                        ecdsa.SignData(
                            System.Text.Encoding.UTF8.GetBytes("sigstore"),
                            System.Security.Cryptography.HashAlgorithmName.SHA256))
                }
            };
            var response = await httpClient.PostAsJsonAsync(
                "http://fulcio-sigstore.dev.localhost:5555/api/v2/signingCert",
                body, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Fulcio issuance proof failed.");
            return false;
        }
    }

    private static string? ExtractKidFromJwt(string jwt)
    {
        var parts = jwt.Trim().Split('.');
        if (parts.Length < 2) return null;
        try
        {
            var s = parts[0].Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            var headerJson = Convert.FromBase64String(s);
            using var doc = System.Text.Json.JsonDocument.Parse(headerJson);
            return doc.RootElement.TryGetProperty("kid", out var kid)
                ? kid.GetString()
                : null;
        }
        catch { return null; }
    }

    private async Task<ExecuteCommandResult> ExecutePublishTrustedRootCoreAsync(
        OperationExecution execution,
        CancellationToken requestCancellationToken)
    {
        await execution.ReportAsync(
            "preflight",
            0,
            "Validating current trust, TUF, and resource state for trusted-root publication.");

        SigstoreOperationSnapshot before;
        SigstoreResourceInstanceSnapshot workerBefore;
        ExecuteCommandResult workerStart;
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-publish-trusted-root-preflight"))
        {
            requestCancellationToken.ThrowIfCancellationRequested();
            if (!await ValidatePreconditionsAsync(
                    execution,
                    requestCancellationToken))
            {
                return execution.Failure(
                    "Trusted-root publication preconditions are not satisfied.");
            }

            before = await CaptureAsync(requestCancellationToken);
            execution.Before = before;
            if (!ValidateCapture(
                    execution,
                    "preflight",
                    before))
            {
                return execution.Failure(
                    "The current TUF repository is not internally consistent.");
            }

            workerBefore = runtime.GetRequiredSnapshot(
                resource.Components.TufBootstrap.Resource);
            if (!execution.Check(
                    "worker-ready",
                    IsSuccessfulTerminal(workerBefore),
                    "a completed one-shot with exit code 0",
                    Describe(workerBefore),
                    "preflight",
                    workerBefore.Resource))
            {
                return execution.Failure(
                    "The TUF worker is not ready for a new one-shot run.");
            }
            if (!execution.Check(
                    "worker-baseline-identity",
                    HasContainerIdentity(workerBefore),
                    "a non-empty container identity",
                    workerBefore.ContainerId ?? "missing",
                    "preflight",
                    workerBefore.Resource))
            {
                return execution.Failure(
                    "The completed TUF worker has no observable container identity.");
            }

            await execution.ReportAsync(
                "write-signal",
                1,
                "Writing publish-trusted-root.request signal file for the TUF worker.");

            var operationId = Guid.NewGuid().ToString("N");
            var signalPath = Path.Combine(
                resource.StatePath,
                "publish-trusted-root.request");

            // Use FileMode.CreateNew to atomically reject if a surviving request
            // file exists — never overwrite replay correlation.
            var requestContent = System.Text.Json.JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                operationId = operationId,
                trustDomainId = before.Tuf.Trust.TrustDomainId
            });
            try
            {
                await using var fs = new FileStream(
                    signalPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None);
                var bytes = System.Text.Encoding.UTF8.GetBytes(requestContent);
                await fs.WriteAsync(bytes, requestCancellationToken);
                await fs.FlushAsync(requestCancellationToken);
            }
            catch (IOException ex) when (ex.HResult == unchecked((int)0x80070050) /* ERROR_FILE_EXISTS */
                || File.Exists(signalPath))
            {
                execution.AddError(
                    execution.Phase,
                    resource.Name,
                    null,
                    "A publish-trusted-root.request file already exists from a prior " +
                    "interrupted operation. The TUF worker must consume it on restart " +
                    "before a new operation can be issued.");
                return execution.Failure(
                    "Cannot issue publish-trusted-root: surviving request file exists");
            }

            await execution.ReportAsync(
                "start-worker",
                2,
                "Starting a new TUF one-shot while handing off state.lock.");

            using var critical = new CancellationTokenSource(WorkerTimeout);
            workerStart = await runtime.ExecuteCommandAsync(
                resource.Components.TufBootstrap.Resource,
                KnownResourceCommands.StartCommand,
                critical.Token);
        }

        if (!workerStart.Success)
        {
            execution.AddError(
                "start-worker",
                resource.Components.TufBootstrap.Resource.Name,
                null,
                workerStart.Message
                    ?? "Aspire rejected the TUF worker start command.");
            return await CompleteWorkerFailureAsync(
                execution,
                before,
                "The TUF worker could not be started for trusted-root publication.");
        }

        await execution.ReportAsync(
            "wait-worker",
            3,
            "Waiting for the trusted-root publication worker to complete.");

        SigstoreResourceInstanceSnapshot workerAfter;
        using (var critical = new CancellationTokenSource(WorkerTimeout))
        {
            try
            {
                workerAfter = await runtime.WaitForSnapshotAsync(
                    resource.Components.TufBootstrap.Resource,
                    snapshot => IsNewInstance(workerBefore, snapshot)
                        && IsTerminal(snapshot),
                    WorkerTimeout,
                    critical.Token);
            }
            catch (OperationCanceledException exception)
            {
                execution.AddError(
                    "wait-worker",
                    resource.Components.TufBootstrap.Resource.Name,
                    null,
                    exception.Message);
                return await CompleteWorkerFailureAsync(
                    execution,
                    before,
                    "The publication worker did not complete within the timeout.");
            }
        }

        execution.Resources.Add(
            CreateLifecycleResult(
                resource.Components.TufBootstrap.Resource.Name,
                KnownResourceCommands.StartCommand,
                workerBefore,
                workerAfter,
                null));
        if (!IsSuccessfulTerminal(workerAfter))
        {
            execution.AddError(
                "wait-worker",
                workerAfter.Resource,
                null,
                $"Worker completed as {Describe(workerAfter)}.");
            return await CompleteWorkerFailureAsync(
                execution,
                before,
                "The trusted-root publication worker failed.");
        }

        await execution.ReportAsync(
            "postconditions",
            4,
            "Validating generation advance, additive material, and TUF target coherence.");

        using var postconditionToken = new CancellationTokenSource(WorkerTimeout);
        SigstoreOperationSnapshot after;
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-publish-trusted-root-postconditions"))
        {
            after = await CaptureAsync(postconditionToken.Token);
            execution.After = after;
            ValidatePublishPostconditions(execution, before, after, workerBefore, workerAfter);
        }

        if (execution.HasFailures)
        {
            return execution.Failure(
                "Trusted-root published, but postconditions failed.");
        }

        // Restart all clients since none support in-process TUF refresh.
        await execution.ReportAsync(
            "restart-clients",
            5,
            "Restarting all six clients to pick up new trust material.");

        var clients = resource
            .GetRegistrations()
            .Clients
            .OrderBy(client => client.Resource.Name, StringComparer.Ordinal)
            .ToArray();
        if (!execution.Check(
                "six-clients-registered",
                clients.Length == 6,
                "6",
                clients.Length.ToString(CultureInfo.InvariantCulture),
                "restart-clients",
                resource.Name))
        {
            return execution.Failure(
                "The Sigstore parent does not have exactly six clients.");
        }

        using var clientCritical = new CancellationTokenSource(
            TimeSpan.FromMinutes(20));
        var completed = 6;
        foreach (var client in clients)
        {
            var clientBefore = runtime.GetRequiredSnapshot(client.Resource);
            if (!execution.Check(
                    $"{client.Resource.Name}-ready",
                    IsRunningHealthy(clientBefore)
                        && HasContainerIdentity(clientBefore),
                    "Running/Healthy with a container identity",
                    Describe(clientBefore),
                    "restart-client",
                    client.Resource.Name))
            {
                return execution.Failure(
                    $"{client.Resource.Name} is not ready to restart.");
            }

            await execution.ReportAsync(
                "restart-client",
                completed,
                $"Restarting {client.Resource.Name} (restart uptake - no in-process refresh).");
            var restart = await runtime.ExecuteCommandAsync(
                client.Resource,
                KnownResourceCommands.RestartCommand,
                clientCritical.Token);
            if (!restart.Success)
            {
                execution.AddError(
                    "restart-client",
                    client.Resource.Name,
                    null,
                    restart.Message
                        ?? "Aspire rejected the client restart command.");
                return execution.Failure(
                    $"{client.Resource.Name} could not be restarted.");
            }

            SigstoreResourceInstanceSnapshot clientAfter;
            try
            {
                clientAfter = await runtime.WaitForSnapshotAsync(
                    client.Resource,
                    snapshot => IsNewInstance(clientBefore, snapshot)
                        && IsRunningHealthy(snapshot),
                    ClientTimeout,
                    clientCritical.Token);
            }
            catch (OperationCanceledException exception)
            {
                execution.AddError(
                    "wait-client",
                    client.Resource.Name,
                    null,
                    exception.Message);
                return execution.Failure(
                    $"{client.Resource.Name} did not become healthy after restart.");
            }

            var trustStatus = await runtime.ReadClientStatusAsync(
                client,
                clientCritical.Token);
            if (!execution.Check(
                    $"{client.Resource.Name}-trust-status",
                    MatchesDisk(after.Tuf.Trust, trustStatus),
                    DescribeTrust(after.Tuf.Trust),
                    DescribeTrust(trustStatus),
                    "wait-client",
                    client.Resource.Name))
            {
                return execution.Failure(
                    $"{client.Resource.Name} reported inconsistent trust after " +
                    "trusted-root publication (stale client detected).");
            }

            execution.Resources.Add(
                CreateLifecycleResult(
                    client.Resource.Name,
                    KnownResourceCommands.RestartCommand,
                    clientBefore,
                    clientAfter,
                    trustStatus));
            completed++;
        }

        await execution.ReportAsync(
            "aggregate-status",
            10,
            "Waiting for aggregate health and verifying all client convergence.");
        await runtime.WaitForAggregateHealthyAsync(
            AggregateTimeout,
            clientCritical.Token);
        var aggregate = await runtime.CollectStatusAsync(clientCritical.Token);
        execution.Check(
            "aggregate-status-ready",
            aggregate.Ready
                && aggregate.Clients.Count == clients.Length,
            $"ready=true and {clients.Length} clients",
            aggregate.Reason
                ?? $"ready={aggregate.Ready}, clients={aggregate.Clients.Count}",
            "aggregate-status",
            resource.Name);

        await execution.ReportAsync(
            "final-verification",
            11,
            "Final TUF server identity and served metadata check.");
        var finalServer = runtime.GetRequiredSnapshot(
            resource.Components.Tuf.Resource);
        execution.Check(
            "tuf-server-final-identity",
            SameInstance(after.TufServer, finalServer)
                && IsRunningHealthy(finalServer),
            Describe(after.TufServer),
            Describe(finalServer),
            "final-verification",
            finalServer.Resource);

        if (execution.HasFailures)
        {
            return execution.Failure(
                "Trusted-root publication completed but one or more " +
                "convergence checks failed.");
        }

        await execution.ReportAsync(
            "complete",
            12,
            "Trusted-root published, all clients converged on new trust material.");
        return execution.Success(
            "Additive trusted-root update published and verified across all clients.");
    }

    private static void ValidatePublishPostconditions(
        OperationExecution execution,
        SigstoreOperationSnapshot before,
        SigstoreOperationSnapshot after,
        SigstoreResourceInstanceSnapshot workerBefore,
        SigstoreResourceInstanceSnapshot workerAfter)
    {
        // Generation must advance by exactly 1.
        execution.Check(
            "generation-advanced",
            after.Tuf.Trust.Generation == before.Tuf.Trust.Generation + 1
                && after.Tuf.Trust.GenerationId != before.Tuf.Trust.GenerationId
                && after.Tuf.Trust.GenerationManifestSha256
                    != before.Tuf.Trust.GenerationManifestSha256,
            $"generation {before.Tuf.Trust.Generation + 1} with changed identity",
            $"generation {after.Tuf.Trust.Generation}, id " +
                $"{after.Tuf.Trust.GenerationId}",
            "postconditions",
            "tuf-bootstrap");

        // Trust domain must be preserved.
        CheckEqual(
            execution,
            "trust-domain-unchanged",
            before.Tuf.Trust.TrustDomainId,
            after.Tuf.Trust.TrustDomainId);

        // TrustedRoot must change (additive material added).
        execution.Check(
            "trusted-root-changed",
            after.Tuf.Metadata.TrustedRootSha256
                != before.Tuf.Metadata.TrustedRootSha256,
            "a changed trusted-root hash",
            after.Tuf.Metadata.TrustedRootSha256,
            "postconditions",
            "tuf-bootstrap");

        // Root must be unchanged (no root rotation during publish).
        CheckEqual(
            execution,
            "root-unchanged",
            before.Tuf.Metadata.Root,
            after.Tuf.Metadata.Root);

        // Bootstrap root must be unchanged.
        CheckEqual(
            execution,
            "bootstrap-root-unchanged",
            before.Tuf.BootstrapRootSha256,
            after.Tuf.BootstrapRootSha256);

        // Targets must advance (new target content).
        execution.Check(
            "targets-version-advanced",
            after.Tuf.Metadata.Targets.Version
                > before.Tuf.Metadata.Targets.Version
                && after.Tuf.Metadata.Targets.Sha256
                    != before.Tuf.Metadata.Targets.Sha256,
            $"targets version > {before.Tuf.Metadata.Targets.Version} " +
                "with changed hash",
            $"targets version {after.Tuf.Metadata.Targets.Version}, " +
                $"sha256 {after.Tuf.Metadata.Targets.Sha256}",
            "postconditions",
            "tuf-bootstrap");

        // Snapshot and timestamp must advance.
        CheckAdvanced(
            execution,
            "snapshot-advanced",
            before.Tuf.Metadata.Snapshot,
            after.Tuf.Metadata.Snapshot);
        CheckAdvanced(
            execution,
            "timestamp-advanced",
            before.Tuf.Metadata.Timestamp,
            after.Tuf.Metadata.Timestamp);

        // Publication must advance.
        execution.Check(
            "publication-advanced",
            before.Tuf.Trust.PublicationId
                    != after.Tuf.Trust.PublicationId
                && before.Tuf.Trust.PublicationManifestSha256
                    != after.Tuf.Trust.PublicationManifestSha256,
            DescribePublication(before.Tuf.Trust),
            DescribePublication(after.Tuf.Trust),
            "postconditions",
            "tuf-bootstrap");

        // History must retain prior publication.
        execution.Check(
            "history-retains-prior-active",
            after.Tuf.PreviousPublicationId
                    == before.Tuf.Trust.PublicationId
                && after.Tuf.PreviousPublicationManifestSha256
                    == before.Tuf.Trust.PublicationManifestSha256,
            DescribePublication(before.Tuf.Trust),
            $"{after.Tuf.PreviousPublicationId}/" +
                after.Tuf.PreviousPublicationManifestSha256,
            "postconditions",
            "tuf-bootstrap");

        // Trust state must have changed.
        execution.Check(
            "trust-state-changed",
            before.TrustStateSha256 != after.TrustStateSha256,
            "a changed trust-state fingerprint",
            after.TrustStateSha256,
            "postconditions",
            "tuf-bootstrap");

        // Trust material must have changed (new key added).
        execution.Check(
            "trust-material-changed",
            before.TrustMaterialSha256 != after.TrustMaterialSha256,
            "changed trust material (additive)",
            after.TrustMaterialSha256,
            "postconditions",
            "tuf-bootstrap");

        // Disk/served must be consistent.
        execution.Check(
            "disk-served-after-publish",
            MatchesServed(after.Tuf, after.Served),
            Describe(after.Tuf),
            Describe(after.Served),
            "postconditions",
            after.TufServer.Resource);

        // TUF server not restarted.
        execution.Check(
            "tuf-server-not-restarted",
            SameInstance(before.TufServer, after.TufServer)
                && IsRunningHealthy(after.TufServer),
            Describe(before.TufServer),
            Describe(after.TufServer),
            "postconditions",
            after.TufServer.Resource);

        // Worker ran once.
        execution.Check(
            "worker-ran-once",
            IsNewInstance(workerBefore, workerAfter)
                && IsSuccessfulTerminal(workerAfter),
            Describe(workerBefore),
            Describe(workerAfter),
            "postconditions",
            workerAfter.Resource);
    }

    private async Task<ExecuteCommandResult> ExecuteRefreshTufCoreAsync(
        OperationExecution execution,
        CancellationToken requestCancellationToken)
    {
        await execution.ReportAsync(
            "preflight",
            0,
            "Validating current trust, TUF, and resource state.");

        SigstoreOperationSnapshot before;
        SigstoreResourceInstanceSnapshot workerBefore;
        ExecuteCommandResult workerStart;
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-refresh-tuf-preflight"))
        {
            requestCancellationToken.ThrowIfCancellationRequested();
            if (!await ValidatePreconditionsAsync(
                    execution,
                    requestCancellationToken))
            {
                return execution.Failure(
                    "TUF refresh preconditions are not satisfied.");
            }

            before = await CaptureAsync(requestCancellationToken);
            execution.Before = before;
            if (!ValidateCapture(
                    execution,
                    "preflight",
                    before))
            {
                return execution.Failure(
                    "The current TUF repository is not internally consistent.");
            }

            workerBefore = runtime.GetRequiredSnapshot(
                resource.Components.TufBootstrap.Resource);
            if (!execution.Check(
                    "worker-ready",
                    IsSuccessfulTerminal(workerBefore),
                    "a completed one-shot with exit code 0",
                    Describe(workerBefore),
                    "preflight",
                    workerBefore.Resource))
            {
                return execution.Failure(
                    "The TUF worker is not ready for a new one-shot run.");
            }
            if (!execution.Check(
                    "worker-baseline-identity",
                    HasContainerIdentity(workerBefore),
                    "a non-empty container identity",
                    workerBefore.ContainerId ?? "missing",
                    "preflight",
                    workerBefore.Resource))
            {
                return execution.Failure(
                    "The completed TUF worker has no observable container identity.");
            }

            await execution.ReportAsync(
                "start-worker",
                1,
                "Starting a new TUF one-shot while handing off state.lock.");

            using var critical = new CancellationTokenSource(WorkerTimeout);
            workerStart = await runtime.ExecuteCommandAsync(
                resource.Components.TufBootstrap.Resource,
                KnownResourceCommands.StartCommand,
                critical.Token);
        }

        if (!workerStart.Success)
        {
            execution.AddError(
                "start-worker",
                resource.Components.TufBootstrap.Resource.Name,
                null,
                workerStart.Message
                    ?? "Aspire rejected the TUF worker start command.");
            return await CompleteWorkerFailureAsync(
                execution,
                before,
                "The TUF worker could not be started.");
        }

        await execution.ReportAsync(
            "wait-worker",
            2,
            "Waiting for the new TUF worker instance to complete.");

        SigstoreResourceInstanceSnapshot workerAfter;
        using (var critical = new CancellationTokenSource(WorkerTimeout))
        {
            try
            {
                workerAfter = await runtime.WaitForSnapshotAsync(
                    resource.Components.TufBootstrap.Resource,
                    snapshot => IsNewInstance(workerBefore, snapshot)
                        && IsTerminal(snapshot),
                    WorkerTimeout,
                    critical.Token);
            }
            catch (OperationCanceledException exception)
            {
                execution.AddError(
                    "wait-worker",
                    resource.Components.TufBootstrap.Resource.Name,
                    null,
                    exception.Message);
                return await CompleteWorkerFailureAsync(
                    execution,
                    before,
                    "The TUF worker did not complete within the operation timeout.");
            }
        }

        execution.Resources.Add(
            CreateLifecycleResult(
                resource.Components.TufBootstrap.Resource.Name,
                KnownResourceCommands.StartCommand,
                workerBefore,
                workerAfter,
                null));
        if (!IsSuccessfulTerminal(workerAfter))
        {
            execution.AddError(
                "wait-worker",
                workerAfter.Resource,
                null,
                $"Worker completed as {Describe(workerAfter)}.");
            return await CompleteWorkerFailureAsync(
                execution,
                before,
                "The TUF worker failed.");
        }

        await execution.ReportAsync(
            "postconditions",
            3,
            "Validating committed metadata, history, and the running TUF server.");

        using var postconditionToken = new CancellationTokenSource(
            WorkerTimeout);
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-refresh-tuf-postconditions"))
        {
            var after = await CaptureAsync(postconditionToken.Token);
            execution.After = after;
            ValidateRefreshPostconditions(
                execution,
                before,
                after,
                workerBefore,
                workerAfter);

            await execution.ReportAsync(
                "aggregate-status",
                4,
                "Validating served metadata and all six client trust contracts.");
            var aggregate = await runtime.CollectStatusAsync(
                postconditionToken.Token);
            execution.Check(
                "aggregate-status-ready",
                aggregate.Ready,
                "ready=true with no status errors",
                aggregate.Reason ?? "ready",
                "aggregate-status",
                resource.Name);

            await execution.ReportAsync(
                "final-verification",
                5,
                "Rechecking the TUF server identity before reporting success.");
            var finalServer = runtime.GetRequiredSnapshot(
                resource.Components.Tuf.Resource);
            execution.Check(
                "tuf-server-final-identity",
                SameInstance(after.TufServer, finalServer)
                    && IsRunningHealthy(finalServer),
                Describe(after.TufServer),
                Describe(finalServer),
                "aggregate-status",
                finalServer.Resource);
        }

        if (execution.HasFailures)
        {
            return execution.Failure(
                "TUF metadata refreshed, but one or more postconditions failed.");
        }

        await execution.ReportAsync(
            "complete",
            6,
            "TUF snapshot and timestamp metadata refreshed successfully.");
        return execution.Success(
            "TUF snapshot and timestamp metadata refreshed and verified.");
    }

    private async Task<ExecuteCommandResult> ExecuteRotateTufRootCoreAsync(
        OperationExecution execution,
        CancellationToken requestCancellationToken)
    {
        await execution.ReportAsync(
            "preflight",
            0,
            "Validating current trust, TUF, and resource state for root rotation.");

        SigstoreOperationSnapshot before;
        SigstoreResourceInstanceSnapshot workerBefore;
        ExecuteCommandResult workerStart;
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-rotate-tuf-root-preflight"))
        {
            requestCancellationToken.ThrowIfCancellationRequested();
            if (!await ValidatePreconditionsAsync(
                    execution,
                    requestCancellationToken))
            {
                return execution.Failure(
                    "TUF root rotation preconditions are not satisfied.");
            }

            before = await CaptureAsync(requestCancellationToken);
            execution.Before = before;
            if (!ValidateCapture(
                    execution,
                    "preflight",
                    before))
            {
                return execution.Failure(
                    "The current TUF repository is not internally consistent.");
            }

            workerBefore = runtime.GetRequiredSnapshot(
                resource.Components.TufBootstrap.Resource);
            if (!execution.Check(
                    "worker-ready",
                    IsSuccessfulTerminal(workerBefore),
                    "a completed one-shot with exit code 0",
                    Describe(workerBefore),
                    "preflight",
                    workerBefore.Resource))
            {
                return execution.Failure(
                    "The TUF worker is not ready for a new one-shot run.");
            }
            if (!execution.Check(
                    "worker-baseline-identity",
                    HasContainerIdentity(workerBefore),
                    "a non-empty container identity",
                    workerBefore.ContainerId ?? "missing",
                    "preflight",
                    workerBefore.Resource))
            {
                return execution.Failure(
                    "The completed TUF worker has no observable container identity.");
            }

            await execution.ReportAsync(
                "write-signal",
                1,
                "Writing rotate-root.request signal file for the TUF worker.");

            // Write the signal file that tells the Go worker to rotate
            // instead of refresh. The file is in the state directory root
            // (not inside the TUF layout) to avoid layout validation failure.
            var signalPath = Path.Combine(
                resource.StatePath,
                "rotate-root.request");
            await File.WriteAllTextAsync(
                signalPath,
                "rotate",
                requestCancellationToken);

            await execution.ReportAsync(
                "start-worker",
                2,
                "Starting a new TUF one-shot while handing off state.lock.");

            using var critical = new CancellationTokenSource(WorkerTimeout);
            workerStart = await runtime.ExecuteCommandAsync(
                resource.Components.TufBootstrap.Resource,
                KnownResourceCommands.StartCommand,
                critical.Token);
        }

        if (!workerStart.Success)
        {
            execution.AddError(
                "start-worker",
                resource.Components.TufBootstrap.Resource.Name,
                null,
                workerStart.Message
                    ?? "Aspire rejected the TUF worker start command.");
            return await CompleteWorkerFailureAsync(
                execution,
                before,
                "The TUF worker could not be started for root rotation.");
        }

        await execution.ReportAsync(
            "wait-worker",
            3,
            "Waiting for the root rotation worker to complete.");

        SigstoreResourceInstanceSnapshot workerAfter;
        using (var critical = new CancellationTokenSource(WorkerTimeout))
        {
            try
            {
                workerAfter = await runtime.WaitForSnapshotAsync(
                    resource.Components.TufBootstrap.Resource,
                    snapshot => IsNewInstance(workerBefore, snapshot)
                        && IsTerminal(snapshot),
                    WorkerTimeout,
                    critical.Token);
            }
            catch (OperationCanceledException exception)
            {
                execution.AddError(
                    "wait-worker",
                    resource.Components.TufBootstrap.Resource.Name,
                    null,
                    exception.Message);
                return await CompleteWorkerFailureAsync(
                    execution,
                    before,
                    "The root rotation worker did not complete within the timeout.");
            }
        }

        execution.Resources.Add(
            CreateLifecycleResult(
                resource.Components.TufBootstrap.Resource.Name,
                KnownResourceCommands.StartCommand,
                workerBefore,
                workerAfter,
                null));
        if (!IsSuccessfulTerminal(workerAfter))
        {
            execution.AddError(
                "wait-worker",
                workerAfter.Resource,
                null,
                $"Worker completed as {Describe(workerAfter)}.");
            return await CompleteWorkerFailureAsync(
                execution,
                before,
                "The root rotation worker failed.");
        }

        await execution.ReportAsync(
            "postconditions",
            4,
            "Validating root version advance, key rotation, and versioned chain.");

        using var postconditionToken = new CancellationTokenSource(
            WorkerTimeout);
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-rotate-tuf-root-postconditions"))
        {
            var after = await CaptureAsync(postconditionToken.Token);
            execution.After = after;
            ValidateRotationPostconditions(
                execution,
                before,
                after,
                workerBefore,
                workerAfter);

            await execution.ReportAsync(
                "aggregate-status",
                5,
                "Checking served metadata; clients will update to new root asynchronously.");
            var aggregate = await runtime.CollectStatusAsync(
                postconditionToken.Token);
            // After rotation, clients may still report the old root version
            // until their next TUF update cycle. This is expected and not a
            // failure - the rotation succeeded if disk/served are consistent.
            if (!aggregate.Ready)
            {
                logger.LogInformation(
                    "Aggregate status not yet ready after rotation " +
                    "(clients may need to refresh): {Reason}",
                    aggregate.Reason);
            }

            await execution.ReportAsync(
                "final-verification",
                6,
                "Rechecking the TUF server identity before reporting success.");
            var finalServer = runtime.GetRequiredSnapshot(
                resource.Components.Tuf.Resource);
            execution.Check(
                "tuf-server-final-identity",
                SameInstance(after.TufServer, finalServer)
                    && IsRunningHealthy(finalServer),
                Describe(after.TufServer),
                Describe(finalServer),
                "aggregate-status",
                finalServer.Resource);
        }

        if (execution.HasFailures)
        {
            return execution.Failure(
                "Root rotation completed, but one or more postconditions failed.");
        }

        await execution.ReportAsync(
            "complete",
            7,
            "TUF root key rotated successfully. Root version advanced by 1.");
        return execution.Success(
            "TUF root key rotated, signed by old and new keys, and verified.");
    }

    private async Task<ExecuteCommandResult> ExecuteRestartClientsCoreAsync(
        OperationExecution execution,
        CancellationToken requestCancellationToken)
    {
        await execution.ReportAsync(
            "preflight",
            0,
            "Validating current trust and all registered clients.");

        using var stateLock = stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-restart-clients");
        requestCancellationToken.ThrowIfCancellationRequested();
        if (!await ValidateRestartPreconditionsAsync(
                execution,
                requestCancellationToken))
        {
            return execution.Failure(
                "Client restart preconditions are not satisfied.");
        }

        var clients = resource
            .GetRegistrations()
            .Clients
            .OrderBy(client => client.Resource.Name, StringComparer.Ordinal)
            .ToArray();
        if (!execution.Check(
                "six-clients-registered",
                clients.Length == 6,
                "6",
                clients.Length.ToString(CultureInfo.InvariantCulture),
                "preflight",
                resource.Name))
        {
            return execution.Failure(
                "The Sigstore parent does not have exactly six clients.");
        }

        var before = await CaptureAsync(requestCancellationToken);
        execution.Before = before;
        if (!ValidateCapture(execution, "preflight", before))
        {
            return execution.Failure(
                "The current trust state is not internally consistent.");
        }

        using var critical = new CancellationTokenSource(
            TimeSpan.FromMinutes(20));
        var completed = 1;
        var restarted = new Dictionary<
            string,
            SigstoreResourceInstanceSnapshot>(
            StringComparer.Ordinal);
        foreach (var client in clients)
        {
            var clientBefore = runtime.GetRequiredSnapshot(client.Resource);
            if (!execution.Check(
                    $"{client.Resource.Name}-ready",
                    IsRunningHealthy(clientBefore)
                        && HasContainerIdentity(clientBefore),
                    "Running/Healthy with a container identity",
                    Describe(clientBefore),
                    "restart-client",
                    client.Resource.Name))
            {
                return CompleteRestartFailure(
                    execution,
                    before,
                    $"{client.Resource.Name} is not ready to restart.");
            }

            await execution.ReportAsync(
                "restart-client",
                completed,
                $"Restarting {client.Resource.Name}.");
            var restart = await runtime.ExecuteCommandAsync(
                client.Resource,
                KnownResourceCommands.RestartCommand,
                critical.Token);
            if (!restart.Success)
            {
                execution.AddError(
                    "restart-client",
                    client.Resource.Name,
                    null,
                    restart.Message
                        ?? "Aspire rejected the client restart command.");
                return CompleteRestartFailure(
                    execution,
                    before,
                    $"{client.Resource.Name} could not be restarted.");
            }

            SigstoreResourceInstanceSnapshot clientAfter;
            try
            {
                clientAfter = await runtime.WaitForSnapshotAsync(
                    client.Resource,
                    snapshot => IsNewInstance(clientBefore, snapshot)
                        && IsRunningHealthy(snapshot),
                    ClientTimeout,
                    critical.Token);
            }
            catch (OperationCanceledException exception)
            {
                execution.AddError(
                    "wait-client",
                    client.Resource.Name,
                    null,
                    exception.Message);
                return CompleteRestartFailure(
                    execution,
                    before,
                    $"{client.Resource.Name} did not become healthy.");
            }

            var trustStatus = await runtime.ReadClientStatusAsync(
                client,
                critical.Token);
            if (!execution.Check(
                    $"{client.Resource.Name}-trust-status",
                    MatchesDisk(before.Tuf.Trust, trustStatus),
                    DescribeTrust(before.Tuf.Trust),
                    DescribeTrust(trustStatus),
                    "wait-client",
                    client.Resource.Name))
            {
                return CompleteRestartFailure(
                    execution,
                    before,
                    $"{client.Resource.Name} reported inconsistent trust.");
            }

            execution.Resources.Add(
                CreateLifecycleResult(
                    client.Resource.Name,
                    KnownResourceCommands.RestartCommand,
                    clientBefore,
                    clientAfter,
                    trustStatus));
            restarted.Add(client.Resource.Name, clientAfter);
            completed++;
        }

        await execution.ReportAsync(
            "aggregate-status",
            7,
            "Waiting for aggregate health and all client status contracts.");
        await runtime.WaitForAggregateHealthyAsync(
            AggregateTimeout,
            critical.Token);
        var aggregate = await runtime.CollectStatusAsync(critical.Token);
        execution.Check(
            "aggregate-status-ready",
            aggregate.Ready
                && aggregate.Clients.Count == clients.Length,
            $"ready=true and {clients.Length} clients",
            aggregate.Reason
                ?? $"ready={aggregate.Ready}, clients={aggregate.Clients.Count}",
            "aggregate-status",
            resource.Name);

        await execution.ReportAsync(
            "postconditions",
            8,
            "Proving trust state stayed byte-identical and clients stayed healthy.");
        var after = await CaptureAsync(critical.Token);
        execution.After = after;
        execution.Check(
            "trust-state-unchanged",
            after.TrustStateSha256 == before.TrustStateSha256,
            before.TrustStateSha256,
            after.TrustStateSha256,
            "postconditions",
            resource.Name);
        execution.Check(
            "tuf-disk-state-unchanged",
            after.Tuf == before.Tuf,
            Describe(before.Tuf),
            Describe(after.Tuf),
            "postconditions",
            resource.Name);
        execution.Check(
            "tuf-served-state-unchanged",
            after.Served == before.Served,
            Describe(before.Served),
            Describe(after.Served),
            "postconditions",
            resource.Components.Tuf.Resource.Name);
        execution.Check(
            "tuf-server-unchanged",
            SameInstance(before.TufServer, after.TufServer)
                && IsRunningHealthy(after.TufServer),
            Describe(before.TufServer),
            Describe(after.TufServer),
            "postconditions",
            resource.Components.Tuf.Resource.Name);

        foreach (var client in clients)
        {
            var final = runtime.GetRequiredSnapshot(client.Resource);
            var expected = restarted[client.Resource.Name];
            execution.Check(
                $"{client.Resource.Name}-final-state",
                SameInstance(expected, final)
                    && IsRunningHealthy(final),
                Describe(expected),
                Describe(final),
                "postconditions",
                client.Resource.Name);
        }

        if (execution.HasFailures)
        {
            return execution.Failure(
                "All client lifecycle commands completed, but one or more " +
                "postconditions failed.");
        }

        await execution.ReportAsync(
            "complete",
            9,
            "All six clients restarted with current verified trust status.");
        return execution.Success(
            "All six Sigstore clients restarted and became healthy.");
    }

    private async Task<bool> ValidatePreconditionsAsync(
        OperationExecution execution,
        CancellationToken cancellationToken)
    {
        var health = resource.GetRuntimeHealth();
        var healthy = execution.Check(
            "parent-runtime-healthy",
            health.State == "Healthy",
            "Healthy",
            health.Reason ?? health.State,
            "preflight",
            resource.Name);
        if (!healthy)
        {
            return false;
        }

        var status = await runtime.CollectStatusAsync(cancellationToken);
        return execution.Check(
            "trust-status-ready",
            status.Ready,
            "ready=true with no status errors",
            status.Reason ?? "ready",
            "preflight",
            resource.Name);
    }

    /// <summary>
    /// Validates preconditions for restart-clients. Accepts stale
    /// tufRootVersion/tufTargetsVersion on clients (valid after root
    /// rotation - clients will catch up on restart). Rejects all other
    /// trust mismatches (domain, generation, trusted-root, signing-config).
    /// </summary>
    private async Task<bool> ValidateRestartPreconditionsAsync(
        OperationExecution execution,
        CancellationToken cancellationToken)
    {
        var health = resource.GetRuntimeHealth();
        var healthy = execution.Check(
            "parent-runtime-healthy",
            health.State == "Healthy",
            "Healthy",
            health.Reason ?? health.State,
            "preflight",
            resource.Name);
        if (!healthy)
        {
            return false;
        }

        var status = await runtime.CollectStatusAsync(cancellationToken);
        if (status.Ready)
        {
            return execution.Check(
                "trust-status-ready",
                true,
                "ready=true with no status errors",
                "ready",
                "preflight",
                resource.Name);
        }

        // After root rotation, clients may report stale tufRootVersion
        // and/or tufTargetsVersion until restarted. This is the valid
        // state that restart-clients is designed to resolve. Reject any
        // errors about domain, generation, trusted-root, or signing-config.
        var unsafeErrors = status.Errors
            .Where(error =>
                !error.Message.StartsWith(
                    "tufRootVersion",
                    StringComparison.Ordinal)
                && !error.Message.StartsWith(
                    "tufTargetsVersion",
                    StringComparison.Ordinal))
            .ToArray();

        if (unsafeErrors.Length != 0)
        {
            return execution.Check(
                "trust-status-ready",
                false,
                "only stale root/targets version errors (post-rotation)",
                $"{unsafeErrors[0].Source}: {unsafeErrors[0].Message}",
                "preflight",
                resource.Name);
        }

        // All errors are stale root/targets versions - acceptable for
        // restart-clients as it will resolve them.
        return execution.Check(
            "trust-status-stale-root-acceptable",
            true,
            "clients have stale root/targets version (will converge on restart)",
            status.Reason ?? "stale root version",
            "preflight",
            resource.Name);
    }

    private async Task<SigstoreOperationSnapshot> CaptureAsync(
        CancellationToken cancellationToken)
    {
        var tuf = stateInspector.ReadTufState(resource.StatePath);
        var trustStateSha256 = stateInspector.ReadTrustStateFingerprint(
            resource.StatePath);
        var trustMaterialSha256 =
            stateInspector.ReadTrustMaterialFingerprint(
                resource.StatePath);
        var served = await runtime.ReadServedTufStateAsync(
            cancellationToken);
        var tufServer = runtime.GetRequiredSnapshot(
            resource.Components.Tuf.Resource);
        return new SigstoreOperationSnapshot(
            tuf,
            served,
            trustStateSha256,
            trustMaterialSha256,
            tufServer);
    }

    internal static async Task<SigstoreOperationSnapshot> CaptureAsync(
        SigstoreResource resource,
        ISigstoreStateInspector stateInspector,
        CancellationToken cancellationToken)
    {
        var tuf = stateInspector.ReadTufState(resource.StatePath);
        var trustStateSha256 = stateInspector.ReadTrustStateFingerprint(
            resource.StatePath);
        var trustMaterialSha256 =
            stateInspector.ReadTrustMaterialFingerprint(
                resource.StatePath);
        // Use a no-op served state when called from external commands
        // that don't need served TUF validation.
        var tufServer = new SigstoreResourceInstanceSnapshot(
            resource.Components.Tuf.Resource.Name,
            "none", "none", "none", null, null, null, null, null);
        return new SigstoreOperationSnapshot(
            tuf,
            new SigstoreServedTufSnapshot(null!, null!),
            trustStateSha256,
            trustMaterialSha256,
            tufServer);
    }

    private static bool ValidateCapture(
        OperationExecution execution,
        string phase,
        SigstoreOperationSnapshot snapshot)
    {
        var consistent = execution.Check(
            $"{phase}-disk-served",
            MatchesServed(snapshot.Tuf, snapshot.Served),
            Describe(snapshot.Tuf),
            Describe(snapshot.Served),
            phase,
            snapshot.TufServer.Resource);
        var serverHealthy = execution.Check(
            $"{phase}-tuf-server",
            IsRunningHealthy(snapshot.TufServer)
                && HasContainerIdentity(snapshot.TufServer),
            "Running/Healthy with a container identity",
            Describe(snapshot.TufServer),
            phase,
            snapshot.TufServer.Resource);
        var metadataCurrent = execution.Check(
            $"{phase}-metadata-current",
            snapshot.Tuf.Metadata.Root.ExpiresAtUtc > DateTimeOffset.UtcNow
                && snapshot.Tuf.Metadata.Targets.ExpiresAtUtc
                    > DateTimeOffset.UtcNow
                && snapshot.Tuf.Metadata.Snapshot.ExpiresAtUtc
                    > DateTimeOffset.UtcNow
                && snapshot.Tuf.Metadata.Timestamp.ExpiresAtUtc
                    > DateTimeOffset.UtcNow,
            "all four metadata roles unexpired",
            Describe(snapshot.Tuf.Metadata),
            phase,
            snapshot.TufServer.Resource);
        return consistent && serverHealthy && metadataCurrent;
    }

    private static void ValidateRefreshPostconditions(
        OperationExecution execution,
        SigstoreOperationSnapshot before,
        SigstoreOperationSnapshot after,
        SigstoreResourceInstanceSnapshot workerBefore,
        SigstoreResourceInstanceSnapshot workerAfter)
    {
        CheckEqual(
            execution,
            "root-unchanged",
            before.Tuf.Metadata.Root,
            after.Tuf.Metadata.Root);
        CheckEqual(
            execution,
            "targets-unchanged",
            before.Tuf.Metadata.Targets,
            after.Tuf.Metadata.Targets);
        CheckEqual(
            execution,
            "trusted-root-unchanged",
            before.Tuf.Metadata.TrustedRootSha256,
            after.Tuf.Metadata.TrustedRootSha256);
        CheckEqual(
            execution,
            "signing-config-unchanged",
            before.Tuf.Metadata.SigningConfigSha256,
            after.Tuf.Metadata.SigningConfigSha256);
        CheckEqual(
            execution,
            "trust-domain-unchanged",
            before.Tuf.Trust.TrustDomainId,
            after.Tuf.Trust.TrustDomainId);
        CheckEqual(
            execution,
            "generation-unchanged",
            DescribeGeneration(before.Tuf.Trust),
            DescribeGeneration(after.Tuf.Trust));
        CheckEqual(
            execution,
            "bootstrap-root-unchanged",
            before.Tuf.BootstrapRootSha256,
            after.Tuf.BootstrapRootSha256);
        CheckEqual(
            execution,
            "source-fingerprint-unchanged",
            before.Tuf.SourceFingerprint,
            after.Tuf.SourceFingerprint);
        CheckEqual(
            execution,
            "trust-material-unchanged",
            before.TrustMaterialSha256,
            after.TrustMaterialSha256);
        CheckEqual(
            execution,
            "tuf-keys-and-target-content-unchanged",
            before.Tuf.StableContentSha256,
            after.Tuf.StableContentSha256);

        CheckAdvanced(
            execution,
            "snapshot-advanced",
            before.Tuf.Metadata.Snapshot,
            after.Tuf.Metadata.Snapshot);
        CheckAdvanced(
            execution,
            "timestamp-advanced",
            before.Tuf.Metadata.Timestamp,
            after.Tuf.Metadata.Timestamp);
        execution.Check(
            "publication-advanced",
            before.Tuf.Trust.PublicationId
                    != after.Tuf.Trust.PublicationId
                && before.Tuf.Trust.PublicationManifestSha256
                    != after.Tuf.Trust.PublicationManifestSha256,
            DescribePublication(before.Tuf.Trust),
            DescribePublication(after.Tuf.Trust),
            "postconditions",
            "tuf-bootstrap");
        execution.Check(
            "history-retains-prior-active",
            after.Tuf.PreviousPublicationId
                    == before.Tuf.Trust.PublicationId
                && after.Tuf.PreviousPublicationManifestSha256
                    == before.Tuf.Trust.PublicationManifestSha256,
            DescribePublication(before.Tuf.Trust),
            $"{after.Tuf.PreviousPublicationId}/" +
                after.Tuf.PreviousPublicationManifestSha256,
            "postconditions",
            "tuf-bootstrap");
        execution.Check(
            "trust-state-changed-only-by-publication",
            before.TrustStateSha256 != after.TrustStateSha256,
            "a changed trust-state fingerprint",
            after.TrustStateSha256,
            "postconditions",
            "tuf-bootstrap");
        execution.Check(
            "disk-served-after-refresh",
            MatchesServed(after.Tuf, after.Served),
            Describe(after.Tuf),
            Describe(after.Served),
            "postconditions",
            after.TufServer.Resource);
        execution.Check(
            "tuf-server-not-restarted",
            SameInstance(before.TufServer, after.TufServer)
                && IsRunningHealthy(after.TufServer),
            Describe(before.TufServer),
            Describe(after.TufServer),
            "postconditions",
            after.TufServer.Resource);
        execution.Check(
            "worker-ran-once",
            IsNewInstance(workerBefore, workerAfter)
                && IsSuccessfulTerminal(workerAfter),
            Describe(workerBefore),
            Describe(workerAfter),
            "postconditions",
            workerAfter.Resource);
    }

    private static void ValidateRotationPostconditions(
        OperationExecution execution,
        SigstoreOperationSnapshot before,
        SigstoreOperationSnapshot after,
        SigstoreResourceInstanceSnapshot workerBefore,
        SigstoreResourceInstanceSnapshot workerAfter)
    {
        // Root must advance by exactly 1.
        execution.Check(
            "root-version-advanced",
            after.Tuf.Metadata.Root.Version
                == before.Tuf.Metadata.Root.Version + 1
                && after.Tuf.Metadata.Root.Sha256
                    != before.Tuf.Metadata.Root.Sha256,
            $"root version {before.Tuf.Metadata.Root.Version + 1} " +
                "with changed hash",
            $"root version {after.Tuf.Metadata.Root.Version}, " +
                $"sha256 {after.Tuf.Metadata.Root.Sha256}",
            "postconditions",
            "tuf-bootstrap");

        // Targets must advance (trust_status target updated with new
        // root version).
        execution.Check(
            "targets-version-advanced",
            after.Tuf.Metadata.Targets.Version
                > before.Tuf.Metadata.Targets.Version
                && after.Tuf.Metadata.Targets.Sha256
                    != before.Tuf.Metadata.Targets.Sha256,
            $"targets version > {before.Tuf.Metadata.Targets.Version} " +
                "with changed hash",
            $"targets version {after.Tuf.Metadata.Targets.Version}, " +
                $"sha256 {after.Tuf.Metadata.Targets.Sha256}",
            "postconditions",
            "tuf-bootstrap");

        // Snapshot and timestamp must advance.
        CheckAdvanced(
            execution,
            "snapshot-advanced",
            before.Tuf.Metadata.Snapshot,
            after.Tuf.Metadata.Snapshot);
        CheckAdvanced(
            execution,
            "timestamp-advanced",
            before.Tuf.Metadata.Timestamp,
            after.Tuf.Metadata.Timestamp);

        // Non-root content must be preserved.
        CheckEqual(
            execution,
            "trusted-root-unchanged",
            before.Tuf.Metadata.TrustedRootSha256,
            after.Tuf.Metadata.TrustedRootSha256);
        CheckEqual(
            execution,
            "signing-config-unchanged",
            before.Tuf.Metadata.SigningConfigSha256,
            after.Tuf.Metadata.SigningConfigSha256);
        CheckEqual(
            execution,
            "trust-domain-unchanged",
            before.Tuf.Trust.TrustDomainId,
            after.Tuf.Trust.TrustDomainId);
        CheckEqual(
            execution,
            "generation-unchanged",
            DescribeGeneration(before.Tuf.Trust),
            DescribeGeneration(after.Tuf.Trust));
        CheckEqual(
            execution,
            "bootstrap-root-unchanged",
            before.Tuf.BootstrapRootSha256,
            after.Tuf.BootstrapRootSha256);
        CheckEqual(
            execution,
            "source-fingerprint-unchanged",
            before.Tuf.SourceFingerprint,
            after.Tuf.SourceFingerprint);
        CheckEqual(
            execution,
            "trust-material-unchanged",
            before.TrustMaterialSha256,
            after.TrustMaterialSha256);

        // Trust status root version must reflect new root.
        execution.Check(
            "trust-status-root-version",
            after.Tuf.Trust.TufRootVersion
                == before.Tuf.Trust.TufRootVersion + 1,
            $"TUF root version {before.Tuf.Trust.TufRootVersion + 1}",
            $"TUF root version {after.Tuf.Trust.TufRootVersion}",
            "postconditions",
            "tuf-bootstrap");

        // Publication must advance.
        execution.Check(
            "publication-advanced",
            before.Tuf.Trust.PublicationId
                    != after.Tuf.Trust.PublicationId
                && before.Tuf.Trust.PublicationManifestSha256
                    != after.Tuf.Trust.PublicationManifestSha256,
            DescribePublication(before.Tuf.Trust),
            DescribePublication(after.Tuf.Trust),
            "postconditions",
            "tuf-bootstrap");
        execution.Check(
            "history-retains-prior-active",
            after.Tuf.PreviousPublicationId
                    == before.Tuf.Trust.PublicationId
                && after.Tuf.PreviousPublicationManifestSha256
                    == before.Tuf.Trust.PublicationManifestSha256,
            DescribePublication(before.Tuf.Trust),
            $"{after.Tuf.PreviousPublicationId}/" +
                after.Tuf.PreviousPublicationManifestSha256,
            "postconditions",
            "tuf-bootstrap");
        execution.Check(
            "trust-state-changed-only-by-publication",
            before.TrustStateSha256 != after.TrustStateSha256,
            "a changed trust-state fingerprint",
            after.TrustStateSha256,
            "postconditions",
            "tuf-bootstrap");
        execution.Check(
            "disk-served-after-rotation",
            MatchesServed(after.Tuf, after.Served),
            Describe(after.Tuf),
            Describe(after.Served),
            "postconditions",
            after.TufServer.Resource);
        execution.Check(
            "tuf-server-not-restarted",
            SameInstance(before.TufServer, after.TufServer)
                && IsRunningHealthy(after.TufServer),
            Describe(before.TufServer),
            Describe(after.TufServer),
            "postconditions",
            after.TufServer.Resource);
        execution.Check(
            "worker-ran-once",
            IsNewInstance(workerBefore, workerAfter)
                && IsSuccessfulTerminal(workerAfter),
            Describe(workerBefore),
            Describe(workerAfter),
            "postconditions",
            workerAfter.Resource);
    }

    private async Task<ExecuteCommandResult> CompleteWorkerFailureAsync(
        OperationExecution execution,
        SigstoreOperationSnapshot before,
        string message)
    {
        await execution.ReportAsync(
            "rollback-validation",
            3,
            "Verifying that the previously committed repository remains served.");
        try
        {
            using var validationToken = new CancellationTokenSource(
                AggregateTimeout);
            using var stateLock = stateInspector.AcquireLock(
                resource.StatePath,
                "dashboard-refresh-tuf-failure-validation");
            var after = await CaptureAsync(validationToken.Token);
            execution.After = after;
            var status = await runtime.CollectStatusAsync(
                validationToken.Token);
            var preserved = execution.Check(
                    "failed-worker-preserved-trust-state",
                    before.TrustStateSha256 == after.TrustStateSha256,
                    before.TrustStateSha256,
                    after.TrustStateSha256,
                    "rollback-validation",
                    "tuf-bootstrap")
                & execution.Check(
                    "failed-worker-preserved-disk-publication",
                    before.Tuf == after.Tuf,
                    Describe(before.Tuf),
                    Describe(after.Tuf),
                    "rollback-validation",
                    "tuf-bootstrap")
                & execution.Check(
                    "failed-worker-preserved-served-publication",
                    before.Served == after.Served,
                    Describe(before.Served),
                    Describe(after.Served),
                    "rollback-validation",
                    resource.Components.Tuf.Resource.Name)
                & execution.Check(
                    "failed-worker-preserved-tuf-server",
                    SameInstance(before.TufServer, after.TufServer)
                        && IsRunningHealthy(after.TufServer),
                    Describe(before.TufServer),
                    Describe(after.TufServer),
                    "rollback-validation",
                    resource.Components.Tuf.Resource.Name)
                & execution.Check(
                    "failed-worker-status-ready",
                    status.Ready,
                    "ready=true",
                    status.Reason ?? "ready",
                    "rollback-validation",
                    resource.Name);
            execution.CommittedStatePreserved = preserved;
        }
        catch (Exception exception)
            when (IsExpectedOperationFailure(exception))
        {
            execution.CommittedStatePreserved = false;
            execution.AddError(
                "rollback-validation",
                "tuf-bootstrap",
                "previous-publication-preserved",
                exception.Message);
        }

        return execution.Failure(message);
    }

    private ExecuteCommandResult CompleteRestartFailure(
        OperationExecution execution,
        SigstoreOperationSnapshot before,
        string message)
    {
        var currentFingerprint = stateInspector.ReadTrustStateFingerprint(
            resource.StatePath);
        execution.CommittedStatePreserved = execution.Check(
            "failed-restart-preserved-trust-state",
            currentFingerprint == before.TrustStateSha256,
            before.TrustStateSha256,
            currentFingerprint,
            "failure-validation",
            resource.Name);
        return execution.Failure(message);
    }

    private static string? ReadOidcKeyIdFromManifest(string statePath)
    {
        var manifestPath = Path.Combine(statePath, "active-generation", "manifest.json");
        if (!File.Exists(manifestPath)) return null;
        var json = File.ReadAllText(manifestPath);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("OidcKeyId", out var kid)
            || doc.RootElement.TryGetProperty("oidcKeyId", out kid))
            return kid.GetString();
        return null;
    }

    private static void CheckEqual<T>(
        OperationExecution execution,
        string name,
        T expected,
        T actual)
        where T : notnull =>
        execution.Check(
            name,
            EqualityComparer<T>.Default.Equals(expected, actual),
            FormatValue(expected),
            FormatValue(actual),
            "postconditions",
            "tuf-bootstrap");

    private static string FormatValue<T>(T value)
        where T : notnull =>
        value switch
        {
            SigstoreTufMetadataRoleStatus role =>
                $"version {role.Version}, sha256 {role.Sha256}, expires " +
                $"{role.ExpiresAtUtc:O}",
            IFormattable formattable => formattable.ToString(
                    null,
                    CultureInfo.InvariantCulture)
                ?? typeof(T).Name,
            _ => value.ToString() ?? typeof(T).Name
        };

    private static void CheckAdvanced(
        OperationExecution execution,
        string name,
        SigstoreTufMetadataRoleStatus before,
        SigstoreTufMetadataRoleStatus after) =>
        execution.Check(
            name,
            after.Version == before.Version + 1
                && after.Sha256 != before.Sha256
                && after.ExpiresAtUtc > before.ExpiresAtUtc
                && after.ExpiresAtUtc > DateTimeOffset.UtcNow,
            $"version {before.Version + 1}, changed hash, later expiration",
            $"version {after.Version}, sha256 {after.Sha256}, expires " +
                $"{after.ExpiresAtUtc:O}",
            "postconditions",
            "tuf-bootstrap");

    private static bool MatchesServed(
        SigstoreTufStateSnapshot disk,
        SigstoreServedTufSnapshot served) =>
        disk.Metadata == served.Metadata
        && disk.Trust.TrustDomainId == served.Trust.TrustDomainId
        && disk.Trust.Generation == served.Trust.Generation
        && disk.Trust.GenerationId == served.Trust.GenerationId
        && disk.Trust.GenerationManifestSha256
            == served.Trust.GenerationManifestSha256
        && disk.Trust.TufRootVersion == served.Trust.TufRootVersion
        && disk.Trust.TufTargetsVersion == served.Trust.TufTargetsVersion
        && disk.Trust.TrustedRootSha256
            == served.Trust.TrustedRootSha256
        && disk.Trust.SigningConfigSha256
            == served.Trust.SigningConfigSha256;

    internal static bool MatchesDisk(
        SigstoreDiskTrustStatus disk,
        SigstoreClientTrustStatus client) =>
        disk.TrustDomainId == client.TrustDomainId
        && disk.Generation == client.Generation
        && disk.GenerationId == client.GenerationId
        && disk.GenerationManifestSha256
            == client.GenerationManifestSha256
        && disk.TufRootVersion == client.TufRootVersion
        && disk.TufTargetsVersion == client.TufTargetsVersion
        && disk.TrustedRootSha256 == client.TrustedRootSha256
        && disk.SigningConfigSha256 == client.SigningConfigSha256;

    internal static bool HasContainerIdentity(
        SigstoreResourceInstanceSnapshot snapshot) =>
        !string.IsNullOrWhiteSpace(snapshot.ContainerId);

    internal static bool IsNewInstance(
        SigstoreResourceInstanceSnapshot before,
        SigstoreResourceInstanceSnapshot after) =>
        HasContainerIdentity(before)
        && HasContainerIdentity(after)
        && before.ContainerId != after.ContainerId
        && (before.StartTimeUtc is null
            || after.StartTimeUtc > before.StartTimeUtc);

    internal static bool SameInstance(
        SigstoreResourceInstanceSnapshot first,
        SigstoreResourceInstanceSnapshot second) =>
        HasContainerIdentity(first)
        && first.ContainerId == second.ContainerId
        && first.StartTimeUtc == second.StartTimeUtc;

    internal static bool IsTerminal(
        SigstoreResourceInstanceSnapshot snapshot) =>
        KnownResourceStates.TerminalStates.Contains(snapshot.State);

    internal static bool IsSuccessfulTerminal(
        SigstoreResourceInstanceSnapshot snapshot) =>
        IsTerminal(snapshot) && snapshot.ExitCode == 0;

    internal static bool IsRunningHealthy(
        SigstoreResourceInstanceSnapshot snapshot) =>
        snapshot.State == KnownResourceStates.Running
        && snapshot.Health == nameof(HealthStatus.Healthy);

    internal static SigstoreResourceLifecycleResult CreateLifecycleResult(
        string resourceName,
        string command,
        SigstoreResourceInstanceSnapshot before,
        SigstoreResourceInstanceSnapshot after,
        SigstoreClientTrustStatus? trustStatus) =>
        new(
            resourceName,
            command,
            before.ContainerId!,
            after.ContainerId!,
            before.StartTimeUtc,
            after.StartTimeUtc,
            after.State,
            after.Health,
            after.ExitCode,
            trustStatus);

    internal static ExecuteCommandResult CreateContentionResult(
        string command,
        SigstoreOperationState active)
    {
        var now = DateTimeOffset.UtcNow;
        return SigstoreOperationCommand.CreateResult(
            new SigstoreOperationResult(
                1,
                command,
                false,
                "contention",
                $"Cannot run {command} because {active.Command} is already " +
                    $"active in phase {active.Phase}.",
                now,
                now,
                [],
                null,
                null,
                [],
                [],
                null,
                [
                    new(
                        "contention",
                        "sigstore",
                        "operation-exclusive",
                        $"{active.Command} has held the operation gate since " +
                            $"{active.StartedAtUtc:O}.")
                ]));
    }

    internal static bool IsExpectedOperationFailure(Exception exception) =>
        exception is SigstoreStatusException
            or IOException
            or UnauthorizedAccessException
            or HttpRequestException
            or InvalidOperationException
            or JsonException
            or UriFormatException
            or OperationCanceledException;

    internal static string Describe(
        SigstoreResourceInstanceSnapshot snapshot) =>
        $"{snapshot.State}/{snapshot.Health}, container " +
        $"{snapshot.ContainerId ?? "missing"}, start " +
        $"{snapshot.StartTimeUtc?.ToString("O") ?? "missing"}, exit " +
        $"{snapshot.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "none"}";

    private static string Describe(SigstoreTufStateSnapshot snapshot) =>
        $"{DescribePublication(snapshot.Trust)}, root " +
        $"{snapshot.Metadata.Root.Version}/{snapshot.Metadata.Root.Sha256}, " +
        $"targets {snapshot.Metadata.Targets.Version}/" +
        $"{snapshot.Metadata.Targets.Sha256}, snapshot " +
        $"{snapshot.Metadata.Snapshot.Version}/" +
        $"{snapshot.Metadata.Snapshot.Sha256}, timestamp " +
        $"{snapshot.Metadata.Timestamp.Version}/" +
        $"{snapshot.Metadata.Timestamp.Sha256}";

    private static string Describe(SigstoreServedTufSnapshot snapshot) =>
        $"root {snapshot.Metadata.Root.Version}/" +
        $"{snapshot.Metadata.Root.Sha256}, targets " +
        $"{snapshot.Metadata.Targets.Version}/" +
        $"{snapshot.Metadata.Targets.Sha256}, snapshot " +
        $"{snapshot.Metadata.Snapshot.Version}/" +
        $"{snapshot.Metadata.Snapshot.Sha256}, timestamp " +
        $"{snapshot.Metadata.Timestamp.Version}/" +
        $"{snapshot.Metadata.Timestamp.Sha256}";

    private static string Describe(SigstoreTufMetadataStatus metadata) =>
        $"root expires {metadata.Root.ExpiresAtUtc:O}, targets expires " +
        $"{metadata.Targets.ExpiresAtUtc:O}, snapshot expires " +
        $"{metadata.Snapshot.ExpiresAtUtc:O}, timestamp expires " +
        $"{metadata.Timestamp.ExpiresAtUtc:O}";

    private static string DescribePublication(
        SigstoreDiskTrustStatus trust) =>
        $"{trust.PublicationId}/{trust.PublicationManifestSha256}";

    private static string DescribeGeneration(
        SigstoreDiskTrustStatus trust) =>
        $"{trust.TrustDomainId}/{trust.Generation}/{trust.GenerationId}/" +
        trust.GenerationManifestSha256;

    internal static string DescribeTrust(
        SigstoreDiskTrustStatus trust) =>
        $"{DescribeGeneration(trust)}/{trust.TufRootVersion}/" +
        $"{trust.TufTargetsVersion}/{trust.TrustedRootSha256}/" +
        trust.SigningConfigSha256;

    internal static string DescribeTrust(
        SigstoreClientTrustStatus trust) =>
        $"{trust.TrustDomainId}/{trust.Generation}/{trust.GenerationId}/" +
        $"{trust.GenerationManifestSha256}/{trust.TufRootVersion}/" +
        $"{trust.TufTargetsVersion}/{trust.TrustedRootSha256}/" +
        trust.SigningConfigSha256;

    private sealed class OperationExecution(
        SigstoreResource resource,
        ISigstoreOperationRuntime runtime,
        ILogger logger,
        SigstoreResource.SigstoreOperationLease lease,
        int total)
    {
        public List<SigstoreOperationProgress> Progress { get; } = [];

        public List<SigstoreResourceLifecycleResult> Resources { get; } = [];

        public List<SigstoreOperationCheck> Checks { get; } = [];

        public List<SigstoreOperationError> Errors { get; } = [];

        public string Phase { get; private set; } = "starting";

        public SigstoreOperationSnapshot? Before { get; set; }

        public SigstoreOperationSnapshot? After { get; set; }

        public bool? CommittedStatePreserved { get; set; }

        public bool HasFailures => Errors.Count != 0;

        public async Task ReportAsync(
            string phase,
            int completed,
            string message)
        {
            Phase = phase;
            var progress = new SigstoreOperationProgress(
                phase,
                completed,
                total,
                message,
                DateTimeOffset.UtcNow);
            Progress.Add(progress);
            lease.Report(
                phase,
                completed,
                total,
                message);
            logger.LogInformation(
                "Sigstore operation {Command} phase {Phase} " +
                "({Completed}/{Total}): {Message}",
                lease.Operation.Command,
                phase,
                completed,
                total,
                message);
            await runtime.PublishParentStateAsync(resource);
        }

        public bool Check(
            string name,
            bool passed,
            string expected,
            string actual,
            string phase,
            string resourceName)
        {
            Checks.Add(
                new SigstoreOperationCheck(
                    name,
                    passed,
                    expected,
                    actual));
            if (!passed)
            {
                AddError(
                    phase,
                    resourceName,
                    name,
                    $"Expected {expected}; observed {actual}.");
            }
            return passed;
        }

        public void AddError(
            string phase,
            string resourceName,
            string? postcondition,
            string message) =>
            Errors.Add(
                new SigstoreOperationError(
                    phase,
                    resourceName,
                    postcondition,
                    message));

        public ExecuteCommandResult Success(string message) =>
            CreateResult(true, message);

        public ExecuteCommandResult Failure(string message) =>
            CreateResult(false, message);

        private ExecuteCommandResult CreateResult(
            bool success,
            string message) =>
            SigstoreOperationCommand.CreateResult(
                new SigstoreOperationResult(
                    1,
                    lease.Operation.Command,
                    success,
                    Phase,
                    message,
                    lease.Operation.StartedAtUtc,
                    DateTimeOffset.UtcNow,
                    Progress,
                    Before,
                    After,
                    Resources,
                    Checks,
                    CommittedStatePreserved,
                    Errors));
    }
}

internal interface ISigstoreOperationRuntime
{
    SigstoreResourceInstanceSnapshot GetRequiredSnapshot(IResource resource);

    Task<ExecuteCommandResult> ExecuteCommandAsync(
        IResource resource,
        string command,
        CancellationToken cancellationToken);

    Task<SigstoreResourceInstanceSnapshot> WaitForSnapshotAsync(
        IResource resource,
        Func<SigstoreResourceInstanceSnapshot, bool> predicate,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    Task WaitForAggregateHealthyAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken);

    Task<SigstoreAggregateTrustStatus> CollectStatusAsync(
        CancellationToken cancellationToken);

    Task<SigstoreServedTufSnapshot> ReadServedTufStateAsync(
        CancellationToken cancellationToken);

    Task<SigstoreClientTrustStatus> ReadClientStatusAsync(
        SigstoreClientRegistration client,
        CancellationToken cancellationToken);

    Task PublishParentStateAsync(SigstoreResource resource);
}

internal sealed class AspireSigstoreOperationRuntime
    : ISigstoreOperationRuntime
{
    private const string ContainerIdProperty = "container.id";

    private readonly SigstoreResource _resource;
    private readonly ResourceCommandService _commands;
    private readonly ResourceNotificationService _notifications;

    public AspireSigstoreOperationRuntime(
        SigstoreResource resource,
        IServiceProvider services)
    {
        _resource = resource;
        _commands = services.GetRequiredService<ResourceCommandService>();
        _notifications =
            services.GetRequiredService<ResourceNotificationService>();
    }

    public SigstoreResourceInstanceSnapshot GetRequiredSnapshot(
        IResource resource)
    {
        if (!_notifications.TryGetCurrentState(
                resource.Name,
                out var resourceEvent))
        {
            throw new InvalidOperationException(
                $"Resource state for '{resource.Name}' is unavailable.");
        }
        return Convert(resourceEvent);
    }

    public Task<ExecuteCommandResult> ExecuteCommandAsync(
        IResource resource,
        string command,
        CancellationToken cancellationToken) =>
        _commands.ExecuteCommandAsync(
            resource,
            command,
            cancellationToken);

    public async Task<SigstoreResourceInstanceSnapshot> WaitForSnapshotAsync(
        IResource resource,
        Func<SigstoreResourceInstanceSnapshot, bool> predicate,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var resourceEvent = await _notifications.WaitForResourceAsync(
            resource.Name,
            item => predicate(Convert(item)),
            timeoutSource.Token);
        return Convert(resourceEvent);
    }

    public async Task WaitForAggregateHealthyAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
        timeoutSource.CancelAfter(timeout);
        _ = await _notifications.WaitForResourceAsync(
            _resource.Name,
            _ => _resource.GetRuntimeHealth().State == "Healthy",
            timeoutSource.Token);
    }

    public Task<SigstoreAggregateTrustStatus> CollectStatusAsync(
        CancellationToken cancellationToken) =>
        SigstoreStatusCommand.CollectAsync(
            _resource,
            cancellationToken);

    public async Task<SigstoreServedTufSnapshot> ReadServedTufStateAsync(
        CancellationToken cancellationToken)
    {
        var endpoint = await _resource.TufEndpoint.GetValueAsync(
            cancellationToken)
            ?? throw new SigstoreStatusException(
                "The TUF endpoint is not allocated.");
        return await SigstoreStatusCommand.ReadServedTufSnapshotAsync(
            new Uri(endpoint, UriKind.Absolute),
            cancellationToken);
    }

    public Task<SigstoreClientTrustStatus> ReadClientStatusAsync(
        SigstoreClientRegistration client,
        CancellationToken cancellationToken) =>
        SigstoreStatusCommand.ReadRequiredClientStatusAsync(
            client,
            cancellationToken);

    public Task PublishParentStateAsync(SigstoreResource resource) =>
        _notifications.PublishUpdateAsync(
            resource,
            snapshot => SigstoreParentHealthMonitor.CreateParentSnapshot(
                resource,
                snapshot));

    private static SigstoreResourceInstanceSnapshot Convert(
        ResourceEvent resourceEvent)
    {
        var snapshot = resourceEvent.Snapshot;
        var containerId = snapshot.Properties
            .FirstOrDefault(
                property => string.Equals(
                    property.Name,
                    ContainerIdProperty,
                    StringComparison.Ordinal))
            ?.Value?
            .ToString();
        return new SigstoreResourceInstanceSnapshot(
            resourceEvent.Resource.Name,
            resourceEvent.ResourceId,
            snapshot.State?.Text ?? "Unavailable",
            snapshot.HealthStatus?.ToString() ?? "Unknown",
            snapshot.ExitCode,
            snapshot.CreationTimeStamp,
            snapshot.StartTimeStamp,
            snapshot.StopTimeStamp,
            containerId);
    }
}

internal interface ISigstoreStateInspector
{
    IDisposable AcquireLock(string statePath, string operation);

    SigstoreTufStateSnapshot ReadTufState(string statePath);

    string ReadTrustStateFingerprint(string statePath);

    string ReadTrustMaterialFingerprint(string statePath);
}

internal sealed class SigstoreFileStateInspector : ISigstoreStateInspector
{
    public IDisposable AcquireLock(
        string statePath,
        string operation) =>
        StateFileLock.Acquire(
            statePath,
            TimeSpan.Zero,
            operation);

    public SigstoreTufStateSnapshot ReadTufState(string statePath) =>
        SigstoreStatusCommand.ReadTufStateSnapshot(statePath);

    public string ReadTrustStateFingerprint(string statePath) =>
        SigstoreStatusCommand.ReadTrustStateFingerprint(statePath);

    public string ReadTrustMaterialFingerprint(string statePath) =>
        SigstoreStatusCommand.ReadTrustMaterialFingerprint(statePath);
}

internal sealed record SigstoreResourceInstanceSnapshot(
    string Resource,
    string ResourceId,
    string State,
    string Health,
    int? ExitCode,
    DateTime? CreationTimeUtc,
    DateTime? StartTimeUtc,
    DateTime? StopTimeUtc,
    string? ContainerId);

internal sealed record SigstoreOperationSnapshot(
    SigstoreTufStateSnapshot Tuf,
    SigstoreServedTufSnapshot Served,
    string TrustStateSha256,
    string TrustMaterialSha256,
    SigstoreResourceInstanceSnapshot TufServer);

internal sealed record SigstoreOperationProgress(
    string Phase,
    int Completed,
    int Total,
    string Message,
    DateTimeOffset ObservedAtUtc);

internal sealed record SigstoreResourceLifecycleResult(
    string Resource,
    string Command,
    string BeforeContainerId,
    string AfterContainerId,
    DateTime? BeforeStartTimeUtc,
    DateTime? AfterStartTimeUtc,
    string State,
    string Health,
    int? ExitCode,
    SigstoreClientTrustStatus? TrustStatus);

internal sealed record SigstoreOperationCheck(
    string Name,
    bool Passed,
    string Expected,
    string Actual);

internal sealed record SigstoreOperationError(
    string Phase,
    string Resource,
    string? Postcondition,
    string Message);

internal sealed record SigstoreOperationResult(
    int SchemaVersion,
    string Command,
    bool Success,
    string Phase,
    string Message,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    IReadOnlyList<SigstoreOperationProgress> Progress,
    SigstoreOperationSnapshot? Before,
    SigstoreOperationSnapshot? After,
    IReadOnlyList<SigstoreResourceLifecycleResult> Resources,
    IReadOnlyList<SigstoreOperationCheck> Postconditions,
    bool? CommittedStatePreserved,
    IReadOnlyList<SigstoreOperationError> Errors);
