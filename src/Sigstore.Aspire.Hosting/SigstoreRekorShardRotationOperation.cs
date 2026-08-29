using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Sigstore.Bootstrap;

namespace Aspire.Hosting.ApplicationModel;

/// <summary>
/// Implements <c>rotate-rekor-shard</c>: a bounded, one-time rotation from
/// the single primary Rekor shard to exactly one predeclared secondary
/// shard. The primary Rekor server is never restarted or mutated. The
/// secondary shard is prepared, started, and proved healthy through the
/// gateway before any TUF publication; only after the Go TUF worker commits
/// an additive TrustedRoot entry (the old shard remains verifiable) and an
/// exclusive new SigningConfig (new entries route only to the secondary)
/// does this operation activate the secondary as a required resource and
/// mark the primary Rekor server historical (removed from the required
/// aggregate-health set, since it no longer serves new writes, while the
/// shared gateway — which still verifies its static tiles/checkpoint —
/// remains required), then converge all six clients. Before that commit is
/// proven, the primary must remain a required resource; after it, a
/// stopped primary can no longer degrade the parent. Repeated invocation
/// after a completed rotation is rejected without mutation; an incomplete
/// operation resumes idempotently from its durable hosting journal,
/// including safely replaying the activate/historical transition.
/// </summary>
internal sealed partial class SigstoreOperationExecutor
{
    private const string RekorRequestedStatus =
        SigstoreRekorShard.StatusRequested;
    private const string RekorCandidateGeneratedStatus =
        SigstoreRekorShard.StatusCandidateGenerated;
    private const string RekorSecondaryPreparedStatus =
        SigstoreRekorShard.StatusSecondaryPrepared;
    private const string RekorSecondaryStartedStatus =
        SigstoreRekorShard.StatusSecondaryStarted;
    private const string RekorSecondaryProvedStatus =
        SigstoreRekorShard.StatusSecondaryProved;
    private const string RekorWorkerCommittedStatus =
        SigstoreRekorShard.StatusWorkerCommitted;
    private const string RekorSecondaryActivatedStatus =
        SigstoreRekorShard.StatusSecondaryActivated;
    private const string RekorClientsConvergedStatus =
        SigstoreRekorShard.StatusClientsConverged;
    private const string RekorCompletedStatus =
        SigstoreRekorShard.StatusCompleted;

    private const string RekorPrimaryUrl =
        "http://rekor-sigstore.dev.localhost:3000";
    private const string RekorSecondaryUrl =
        "http://rekor-secondary-sigstore.dev.localhost:3000";
    private const string RekorSecondaryOrigin =
        "rekor-secondary-sigstore.dev.localhost";
    private const string RekorSecondaryDataRelativePath =
        "data/rekor-shards/secondary";
    /// <summary>
    /// The shared gateway's internal path-based probe alias for the
    /// secondary shard. Nginx primarily routes by the <c>Host</c> header
    /// to the canonical origin (<see cref="RekorSecondaryOrigin"/>), but
    /// its default server also proxies this path prefix to the same
    /// secondary backend so hosting code can probe it without setting a
    /// custom <c>Host</c> header. This is purely a probing convenience —
    /// it is never used as the shard's identity in the TUF worker
    /// request, the durable catalog, or SigningConfig.
    /// </summary>
    private const string RekorSecondaryProbeAliasPathPrefix =
        "shards/secondary/";

    public async Task<ExecuteCommandResult> ExecuteRotateRekorShardAsync(
        CancellationToken requestCancellationToken)
    {
        requestCancellationToken.ThrowIfCancellationRequested();
        if (!resource.TryBeginOperation(
                SigstoreOperationCommand.RotateRekorShardCommand,
                "Rotating Rekor Shard",
                out var lease,
                out var active))
        {
            return CreateContentionResult(
                SigstoreOperationCommand.RotateRekorShardCommand,
                active!);
        }

        var execution = new OperationExecution(
            resource,
            runtime,
            logger,
            lease!,
            total: 22);
        try
        {
            return await ExecuteRotateRekorShardCoreAsync(
                execution,
                requestCancellationToken);
        }
        catch (Exception exception)
            when (IsExpectedOperationFailure(exception)
                || exception is CryptographicException)
        {
            execution.AddError(
                execution.Phase,
                resource.Name,
                null,
                exception.Message);
            return CreateRekorShardResult(
                execution,
                false,
                $"{SigstoreOperationCommand.RotateRekorShardCommand} " +
                $"failed during {execution.Phase}.",
                null);
        }
        finally
        {
            lease!.Dispose();
            await runtime.PublishParentStateAsync(resource);
        }
    }

    private async Task<ExecuteCommandResult>
        ExecuteRotateRekorShardCoreAsync(
            OperationExecution execution,
            CancellationToken requestCancellationToken)
    {
        await execution.ReportAsync(
            "preflight",
            0,
            "Validating durable trust, resources, and the Rekor shard " +
            "catalog.");

        RekorShardRotationCommandJournal operation;
        SigstoreOperationSnapshot before;
        SigstoreResourceInstanceSnapshot workerBefore;
        SigstoreResourceInstanceSnapshot secondaryBefore;
        var workerStarted = false;
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-rotate-rekor-shard-preflight"))
        {
            requestCancellationToken.ThrowIfCancellationRequested();
            workerBefore = runtime.GetRequiredSnapshot(
                resource.Components.TufBootstrap.Resource);
            var primaryBefore = runtime.GetRequiredSnapshot(
                resource.Components.RekorServer.Resource);
            var gatewayBefore = runtime.GetRequiredSnapshot(
                resource.Components.Rekor.Resource);
            secondaryBefore = runtime.GetRequiredSnapshot(
                resource.Components.RekorServerSecondary.Resource);
            if (!execution.Check(
                    "worker-restartable",
                    IsTerminal(workerBefore)
                        && HasContainerIdentity(workerBefore),
                    "terminal with container identity",
                    Describe(workerBefore),
                    "preflight",
                    workerBefore.Resource)
                || !execution.Check(
                    "primary-running",
                    IsRunningHealthy(primaryBefore)
                        && HasContainerIdentity(primaryBefore),
                    "Running/Healthy with container identity",
                    Describe(primaryBefore),
                    "preflight",
                    primaryBefore.Resource)
                || !execution.Check(
                    "gateway-running",
                    IsRunningHealthy(gatewayBefore)
                        && HasContainerIdentity(gatewayBefore),
                    "Running/Healthy with container identity",
                    Describe(gatewayBefore),
                    "preflight",
                    gatewayBefore.Resource))
            {
                return CreateRekorShardResult(
                    execution,
                    false,
                    "Rekor shard rotation resource preconditions are not " +
                    "satisfied.",
                    null);
            }

            var incomplete = LoadIncompleteRekorShardRotation(
                resource.StatePath);
            var recovering = incomplete is not null;
            if (incomplete is null)
            {
                var existingCatalog = SigstoreRekorShard.TryReadShardCatalog(
                    resource.StatePath);
                if (existingCatalog is { Shards.Count: 2 }
                    || resource.IsConditionalResourceActive(
                        resource.Components.RekorServerSecondary
                            .Resource.Name))
                {
                    execution.AddError(
                        "preflight",
                        resource.Name,
                        null,
                        "A bounded Rekor shard rotation has already " +
                        "completed. Repeated invocation is rejected " +
                        "without mutation.");
                    return CreateRekorShardResult(
                        execution,
                        false,
                        "Rekor shard rotation has already completed.",
                        null);
                }
                if (!await ValidatePreconditionsAsync(
                        execution,
                        requestCancellationToken))
                {
                    return CreateRekorShardResult(
                        execution,
                        false,
                        "Rekor shard rotation preconditions are not " +
                        "satisfied.",
                        null);
                }
            }

            operation = incomplete
                ?? await CreateRekorShardRotationOperationAsync(
                    primaryBefore,
                    requestCancellationToken);
            before = operation.StartingSnapshot;
            execution.Before = before;

            if (operation.StartingGenerationManifestSha256
                != ReadGenerationManifestSha256(
                    resource.StatePath,
                    operation.StartingGenerationId))
            {
                execution.AddError(
                    "preflight",
                    resource.Name,
                    null,
                    "Durable Rekor shard rotation state does not match " +
                    "its immutable starting generation.");
                return CreateRekorShardResult(
                    execution,
                    false,
                    "Rekor shard rotation recovery validation failed.",
                    null);
            }
            if (recovering
                && (!ValidateProtectedResources(
                        execution,
                        operation.ProtectedResources,
                        "preflight")
                    || !ValidatePrimaryRekorServerUnchanged(
                        execution,
                        operation,
                        "preflight")))
            {
                return CreateRekorShardResult(
                    execution,
                    false,
                    "A protected Sigstore service changed during Rekor " +
                    "shard rotation.",
                    null);
            }

            var candidatePath = RekorRotationCandidatePath(
                resource.StatePath,
                operation.OperationId);

            if (operation.Status == RekorRequestedStatus)
            {
                await execution.ReportAsync(
                    "generate-candidate",
                    2,
                    "Generating or validating the operation-bound Rekor " +
                    "shard signer.");
                var candidate =
                    SigstoreStateBootstrapper
                        .EnsureRekorShardRotationCandidate(candidatePath);
                if (candidate.PublicKeySha256
                    == operation.StartingRekorPublicKeySha256)
                {
                    throw new InvalidDataException(
                        "The Rekor rotation candidate must use a " +
                        "distinct signer from the active shard.");
                }
                if (operation.CandidatePublicKeySha256 is not null
                    && operation.CandidatePublicKeySha256
                        != candidate.PublicKeySha256)
                {
                    throw new InvalidDataException(
                        "The Rekor rotation candidate changed during " +
                        "replay.");
                }
                operation = operation with
                {
                    Status = RekorCandidateGeneratedStatus,
                    CandidatePublicKeySha256 = candidate.PublicKeySha256,
                    CandidateLogId = candidate.LogId,
                    CandidateShardId = candidate.ShardId,
                    CandidateStateId = operation.CandidateStateId
                        ?? Guid.NewGuid().ToString("D"),
                    CandidateCreatedAtUtc = operation.CandidateCreatedAtUtc
                        ?? DateTimeOffset.UtcNow
                };
                WriteRekorShardRotationJournal(
                    resource.StatePath,
                    operation);
            }

            if (operation.Status == RekorCandidateGeneratedStatus)
            {
                await execution.ReportAsync(
                    "prepare-secondary",
                    3,
                    "Staging the isolated secondary Rekor runtime signer " +
                    "and durable shard data.");
                var runtimeMaterial =
                    SigstoreStateBootstrapper.StageRekorShardRuntime(
                        resource.StatePath,
                        candidatePath);
                if (runtimeMaterial.PublicKeySha256
                    != operation.CandidatePublicKeySha256)
                {
                    throw new InvalidDataException(
                        "The staged secondary Rekor runtime signer does " +
                        "not match the rotation candidate.");
                }
                PrepareSecondaryShardData(operation);
                operation = operation with
                {
                    Status = RekorSecondaryPreparedStatus
                };
                WriteRekorShardRotationJournal(
                    resource.StatePath,
                    operation);
            }
        }

        if (operation.Status == RekorSecondaryPreparedStatus)
        {
            await execution.ReportAsync(
                "start-secondary",
                5,
                "Starting the secondary Rekor shard.");
            ExecuteCommandResult startResult;
            using (var startToken = new CancellationTokenSource(
                WorkerTimeout))
            {
                startResult = await runtime.ExecuteCommandAsync(
                    resource.Components.RekorServerSecondary.Resource,
                    KnownResourceCommands.StartCommand,
                    startToken.Token);
            }
            if (!startResult.Success)
            {
                resource.SetOperationRecovery(
                    SigstoreOperationCommand.RotateRekorShardCommand,
                    "start-secondary",
                    "Rekor Shard Recovery Pending",
                    "The secondary Rekor shard could not be started; " +
                    "replay is required.");
                await runtime.PublishParentStateAsync(resource);
                execution.AddError(
                    "start-secondary",
                    resource.Components.RekorServerSecondary.Resource.Name,
                    null,
                    startResult.Message
                        ?? "Aspire rejected the secondary Rekor shard " +
                            "start.");
                return CreateRekorShardResult(
                    execution,
                    false,
                    "The secondary Rekor shard could not be started.",
                    null);
            }
            SigstoreResourceInstanceSnapshot secondaryAfter;
            using (var waitToken = new CancellationTokenSource(
                ClientTimeout))
            {
                secondaryAfter = await runtime.WaitForSnapshotAsync(
                    resource.Components.RekorServerSecondary.Resource,
                    snapshot => IsRunningHealthy(snapshot)
                        && HasContainerIdentity(snapshot),
                    ClientTimeout,
                    waitToken.Token);
            }
            execution.Resources.Add(
                CreateLifecycleResult(
                    secondaryAfter.Resource,
                    KnownResourceCommands.StartCommand,
                    secondaryBefore,
                    secondaryAfter,
                    null));
            operation = operation with
            {
                Status = RekorSecondaryStartedStatus,
                SecondaryResourceId = secondaryAfter.ResourceId,
                SecondaryContainerId = secondaryAfter.ContainerId,
                SecondaryStartTimeUtc = secondaryAfter.StartTimeUtc
            };
            WriteRekorShardRotationJournal(resource.StatePath, operation);
        }

        if (operation.Status == RekorSecondaryStartedStatus)
        {
            await execution.ReportAsync(
                "prove-secondary",
                6,
                "Proving the secondary shard is healthy and serving a " +
                "signed checkpoint through the gateway.");
            using var proveToken = new CancellationTokenSource(
                ClientTimeout);
            await ProbeSecondaryHealthThroughGatewayAsync(
                proveToken.Token);
            var candidateSpki = SigstoreRekorShard.ReadCandidatePublicKeySpki(
                RekorRotationCandidatePath(
                    resource.StatePath,
                    operation.OperationId));
            var checkpoint =
                await ProbeSecondaryCheckpointThroughGatewayAsync(
                    candidateSpki,
                    proveToken.Token);
            execution.Check(
                "secondary-checkpoint-log-id",
                checkpoint.SignerKeyHashHex.Length == 8,
                "a bound checkpoint signer key hash",
                checkpoint.SignerKeyHashHex,
                "prove-secondary",
                resource.Components.RekorServerSecondary.Resource.Name);
            operation = operation with
            {
                Status = RekorSecondaryProvedStatus,
                SecondaryCheckpoint = checkpoint
            };
            WriteRekorShardRotationJournal(resource.StatePath, operation);
        }

        if (operation.Status == RekorSecondaryProvedStatus)
        {
            await execution.ReportAsync(
                "write-signal",
                8,
                "Writing the operation-bound Rekor shard rotation " +
                "worker request.");
            WriteRekorShardRotationRequest(resource.StatePath, operation);
            resource.SetOperationRecovery(
                SigstoreOperationCommand.RotateRekorShardCommand,
                "request-written",
                "Rekor Shard Recovery Pending",
                "The operation-bound worker request must be completed " +
                "before other trust mutations.");
            workerStarted = true;
        }

        if (workerStarted)
        {
            await execution.ReportAsync(
                "start-worker",
                9,
                "Starting the dedicated TUF worker for the Rekor shard " +
                "generation.");
            ExecuteCommandResult workerStart;
            using (var workerCritical = new CancellationTokenSource(
                WorkerTimeout))
            {
                workerStart = await runtime.ExecuteCommandAsync(
                    resource.Components.TufBootstrap.Resource,
                    KnownResourceCommands.StartCommand,
                    workerCritical.Token);
            }
            if (!workerStart.Success)
            {
                resource.SetOperationRecovery(
                    SigstoreOperationCommand.RotateRekorShardCommand,
                    "start-worker",
                    "Rekor Shard Recovery Pending",
                    "The durable Rekor shard request exists and must be " +
                    "replayed.");
                await runtime.PublishParentStateAsync(resource);
                execution.AddError(
                    "start-worker",
                    resource.Components.TufBootstrap.Resource.Name,
                    null,
                    workerStart.Message
                        ?? "Aspire rejected the TUF worker start.");
                return CreateRekorShardResult(
                    execution,
                    false,
                    "The Rekor shard rotation worker could not be " +
                    "started.",
                    null);
            }

            await execution.ReportAsync(
                "wait-worker",
                10,
                "Waiting for additive TUF publication and the Rekor " +
                "shard generation switch.");
            SigstoreResourceInstanceSnapshot workerAfter;
            using (var workerWait = new CancellationTokenSource(
                WorkerTimeout))
            {
                workerAfter = await runtime.WaitForSnapshotAsync(
                    resource.Components.TufBootstrap.Resource,
                    snapshot => IsNewInstance(workerBefore, snapshot)
                        && IsTerminal(snapshot),
                    WorkerTimeout,
                    workerWait.Token);
            }
            execution.Resources.Add(
                CreateLifecycleResult(
                    workerAfter.Resource,
                    KnownResourceCommands.StartCommand,
                    workerBefore,
                    workerAfter,
                    null));
            if (!IsSuccessfulTerminal(workerAfter))
            {
                resource.SetOperationRecovery(
                    SigstoreOperationCommand.RotateRekorShardCommand,
                    "worker-failed",
                    "Rekor Shard Recovery Pending",
                    "The durable Rekor shard request must be replayed " +
                    "before other trust mutations.");
                await runtime.PublishParentStateAsync(resource);
                execution.AddError(
                    "wait-worker",
                    workerAfter.Resource,
                    null,
                    $"Worker completed as {Describe(workerAfter)}. " +
                    "Reinvoke the command to replay the durable request.");
                return CreateRekorShardResult(
                    execution,
                    false,
                    "The Rekor shard rotation worker did not complete " +
                    "successfully.",
                    null);
            }
        }

        await execution.ReportAsync(
            "worker-postconditions",
            11,
            "Validating additive Rekor trust and the committed TUF " +
            "publication.");
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateRekorShardCommand,
            "worker-completion-validation",
            "Rekor Shard Recovery Pending",
            "The durable worker result must be validated before " +
            "activation.");
        await runtime.PublishParentStateAsync(resource);

        SigstoreOperationSnapshot after;
        IReadOnlyList<SigstoreRekorTlogEntry> tlogEntries;
        RekorShardCatalog catalog;
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-rotate-rekor-shard-postconditions"))
        {
            using var postToken = new CancellationTokenSource(
                WorkerTimeout);
            after = await CaptureAsync(postToken.Token);
            execution.After = after;
            var completion = ReadRekorShardRotationWorkerCompletion(
                resource.StatePath)
                ?? throw new InvalidDataException(
                    "The Rekor shard rotation worker completion record " +
                    "is missing.");
            ValidateRekorShardRotationCompletion(
                completion,
                operation,
                after);
            tlogEntries = SigstoreRekorShard.ReadTlogEntries(
                resource.StatePath);
            catalog = SigstoreRekorShard.ReadShardCatalog(resource.StatePath);
            operation = operation with
            {
                Status = RekorWorkerCommittedStatus,
                WorkerCompletion = completion
            };
            WriteRekorShardRotationJournal(resource.StatePath, operation);
        }
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateRekorShardCommand,
            "worker-committed",
            "Rekor Shard Activation Pending",
            "Additive Rekor trust is committed; all clients must " +
            "converge before the secondary shard is activated.");
        await runtime.PublishParentStateAsync(resource);

        ValidateRekorShardPublicationPostconditions(
            execution,
            operation,
            before,
            after,
            tlogEntries,
            catalog);
        if (execution.HasFailures)
        {
            return CreateRekorShardResult(
                execution,
                false,
                "Additive Rekor trust was published, but postconditions " +
                "failed.",
                null);
        }

        await execution.ReportAsync(
            "prove-old-artifact",
            12,
            "Proving the retained artifact remains verifiable under the " +
            "additive Rekor trust.");
        using (var oldProofToken = new CancellationTokenSource(
            ClientTimeout))
        {
            var oldReplay = await ReadArtifactRekorTlogEntryAsync(
                operation.OldArtifact.ArtifactId,
                oldProofToken.Token);
            execution.Check(
                "old-artifact-still-verifiable",
                oldReplay.LogIdSha256 == operation.OldArtifactLogIdSha256
                    && oldReplay.LogIndex == operation.OldArtifactLogIndex,
                $"{operation.OldArtifactLogIdSha256}@" +
                    operation.OldArtifactLogIndex.ToString(
                        CultureInfo.InvariantCulture),
                $"{oldReplay.LogIdSha256}@" +
                    oldReplay.LogIndex.ToString(
                        CultureInfo.InvariantCulture),
                "prove-old-artifact",
                resource.Name);
        }
        if (execution.HasFailures)
        {
            return CreateRekorShardResult(
                execution,
                false,
                "The retained artifact no longer verifies under the " +
                "additive Rekor trust.",
                null);
        }

        if (!execution.Check(
                "primary-required-before-activation",
                resource.GetRegistrations().RequiredResources
                    .Any(
                        required => ReferenceEquals(
                            required,
                            resource.Components.RekorServer.Resource)),
                "primary Rekor server still required",
                "primary Rekor server already historical",
                "activate-secondary",
                resource.Components.RekorServer.Resource.Name)
            || !ValidatePrimaryRekorServerUnchanged(
                execution,
                operation,
                "activate-secondary"))
        {
            return CreateRekorShardResult(
                execution,
                false,
                "The primary Rekor server was not safely required and " +
                "unchanged immediately before activation.",
                null);
        }

        await execution.ReportAsync(
            "activate-secondary",
            13,
            "Activating the secondary Rekor shard for aggregate health " +
            "and routing, and marking the primary historical now that " +
            "the additive commit is proven.");
        resource.ActivateConditionalResource(
            resource.Components.RekorServerSecondary.Resource);
        resource.MarkResourceHistorical(
            resource.Components.RekorServer.Resource);
        operation = operation with
        {
            Status = RekorSecondaryActivatedStatus,
            SecondaryActivatedAtUtc = operation.SecondaryActivatedAtUtc
                ?? DateTimeOffset.UtcNow
        };
        WriteRekorShardRotationJournal(resource.StatePath, operation);
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateRekorShardCommand,
            "secondary-activated",
            "Rekor Shard Activation Pending",
            "The secondary shard is active; client convergence and new " +
            "artifact proof remain pending.");
        await runtime.PublishParentStateAsync(resource);

        await execution.ReportAsync(
            "restart-clients",
            14,
            "Converging all six clients on the new Rekor shard routing.");
        var clients = resource.GetRegistrations().Clients
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
            return CreateRekorShardResult(
                execution,
                false,
                "The Sigstore parent does not have exactly six clients.",
                null);
        }

        using (var clientCritical = new CancellationTokenSource(
            TimeSpan.FromMinutes(20)))
        {
            foreach (var (client, index) in clients.Select(
                (client, index) => (client, index)))
            {
                var clientBefore = runtime.GetRequiredSnapshot(
                    client.Resource);
                if (!execution.Check(
                        $"{client.Resource.Name}-ready",
                        IsRunningHealthy(clientBefore)
                            && HasContainerIdentity(clientBefore),
                        "Running/Healthy with container identity",
                        Describe(clientBefore),
                        "restart-client",
                        client.Resource.Name))
                {
                    return CreateRekorShardResult(
                        execution,
                        false,
                        $"{client.Resource.Name} is not ready for " +
                        "convergence.",
                        null);
                }

                SigstoreClientTrustStatus? currentStatus = null;
                try
                {
                    currentStatus = await runtime.ReadClientStatusAsync(
                        client,
                        clientCritical.Token);
                }
                catch (Exception exception)
                    when (IsExpectedOperationFailure(exception))
                {
                    logger.LogInformation(
                        exception,
                        "{Client} requires restart before Rekor shard " +
                        "trust convergence.",
                        client.Resource.Name);
                }

                SigstoreResourceInstanceSnapshot clientAfter;
                string lifecycleCommand;
                if (currentStatus is not null
                    && MatchesDisk(after.Tuf.Trust, currentStatus))
                {
                    clientAfter = clientBefore;
                    lifecycleCommand = "already-converged";
                }
                else
                {
                    await execution.ReportAsync(
                        "restart-client",
                        14 + index,
                        $"Restarting {client.Resource.Name} on the active " +
                        "Rekor shard routing.");
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
                                ?? "Aspire rejected the client restart.");
                        return CreateRekorShardResult(
                            execution,
                            false,
                            $"{client.Resource.Name} could not be " +
                            "restarted.",
                            null);
                    }
                    clientAfter = await runtime.WaitForSnapshotAsync(
                        client.Resource,
                        snapshot => IsNewInstance(clientBefore, snapshot)
                            && IsRunningHealthy(snapshot),
                        ClientTimeout,
                        clientCritical.Token);
                    currentStatus = await runtime.ReadClientStatusAsync(
                        client,
                        clientCritical.Token);
                    lifecycleCommand = KnownResourceCommands.RestartCommand;
                }

                if (!execution.Check(
                        $"{client.Resource.Name}-trust-status",
                        currentStatus is not null
                            && MatchesDisk(after.Tuf.Trust, currentStatus),
                        DescribeTrust(after.Tuf.Trust),
                        currentStatus is null
                            ? "unavailable"
                            : DescribeTrust(currentStatus),
                        "restart-client",
                        client.Resource.Name))
                {
                    return CreateRekorShardResult(
                        execution,
                        false,
                        $"{client.Resource.Name} did not converge on " +
                        "additive Rekor shard trust.",
                        null);
                }
                execution.Resources.Add(
                    CreateLifecycleResult(
                        client.Resource.Name,
                        lifecycleCommand,
                        clientBefore,
                        clientAfter,
                        currentStatus));
                operation = operation with
                {
                    Clients = UpsertRekorClientConvergence(
                        operation.Clients,
                        new RekorShardClientConvergence(
                            client.Resource.Name,
                            clientAfter.ContainerId!,
                            clientAfter.StartTimeUtc,
                            DateTimeOffset.UtcNow,
                            currentStatus!))
                };
                WriteRekorShardRotationJournal(
                    resource.StatePath,
                    operation);
            }
        }

        operation = operation with
        {
            Status = RekorClientsConvergedStatus,
            ClientsConvergedAtUtc = DateTimeOffset.UtcNow
        };
        WriteRekorShardRotationJournal(resource.StatePath, operation);
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateRekorShardCommand,
            "clients-converged",
            "Rekor Shard Verification Pending",
            "All clients trust the additive Rekor generation; a new " +
            "artifact under the secondary shard remains pending.");
        await runtime.PublishParentStateAsync(resource);

        await execution.ReportAsync(
            "prove-new-artifact",
            20,
            "Waiting for a new artifact recorded through the secondary " +
            "Rekor shard.");
        var (newArtifact, newTlogEntry) =
            await WaitForArtifactWithTlogEntryAsync(
                operation.OldArtifact.ArtifactId,
                operation.FulcioRootSha256,
                CancellationToken.None);
        execution.Check(
            "new-artifact-uses-secondary-shard",
            newTlogEntry.LogIdSha256 == operation.CandidatePublicKeySha256,
            operation.CandidatePublicKeySha256
                ?? throw new InvalidDataException(
                    "The Rekor rotation candidate public key is missing."),
            newTlogEntry.LogIdSha256,
            "prove-new-artifact",
            resource.Name);
        if (execution.HasFailures)
        {
            return CreateRekorShardResult(
                execution,
                false,
                "The new artifact was not recorded through the " +
                "secondary Rekor shard.",
                null);
        }
        operation = operation with
        {
            NewArtifact = newArtifact,
            NewArtifactLogIdSha256 = newTlogEntry.LogIdSha256,
            NewArtifactLogIndex = newTlogEntry.LogIndex
        };
        WriteRekorShardRotationJournal(resource.StatePath, operation);

        await execution.ReportAsync(
            "aggregate-status",
            21,
            "Verifying aggregate trust status and unchanged protected " +
            "resources.");
        await runtime.WaitForAggregateHealthyAsync(
            AggregateTimeout,
            CancellationToken.None);
        var aggregate = await runtime.CollectStatusAsync(
            CancellationToken.None);
        execution.Check(
            "aggregate-status-ready",
            aggregate.Ready && aggregate.Clients.Count == clients.Length,
            $"ready=true and {clients.Length} converged clients",
            aggregate.Reason
                ?? $"ready={aggregate.Ready}, " +
                    $"clients={aggregate.Clients.Count}",
            "aggregate-status",
            resource.Name);
        execution.Check(
            "protected-services-not-restarted",
            ValidateProtectedResources(
                execution,
                operation.ProtectedResources,
                "final-verification"),
            "all protected service container identities unchanged",
            "see per-resource postconditions",
            "final-verification",
            resource.Name);
        ValidatePrimaryRekorServerUnchanged(
            execution,
            operation,
            "final-verification");
        if (execution.HasFailures)
        {
            return CreateRekorShardResult(
                execution,
                false,
                "Rekor shard activation completed, but final " +
                "convergence checks failed.",
                null);
        }

        var recovered = operation.StartedAtUtc
            < execution.Progress[0].ObservedAtUtc;
        operation = operation with
        {
            Status = RekorCompletedStatus,
            CompletedAtUtc = DateTimeOffset.UtcNow
        };
        WriteRekorShardRotationJournal(resource.StatePath, operation);
        resource.ClearOperationRecovery(
            SigstoreOperationCommand.RotateRekorShardCommand);
        await execution.ReportAsync(
            "complete",
            22,
            "Rekor shard rotated to the new bounded secondary shard.");
        return CreateRekorShardResult(
            execution,
            true,
            $"Rekor shard rotated: {operation.PriorShardId} -> " +
            $"{operation.CandidateShardId}.",
            BuildRekorShardRotationEvidence(operation, recovered));
    }

    private async Task<RekorShardRotationCommandJournal>
        CreateRekorShardRotationOperationAsync(
            SigstoreResourceInstanceSnapshot primary,
            CancellationToken cancellationToken)
    {
        var starting = await CaptureAsync(cancellationToken);
        if (!MatchesServed(starting.Tuf, starting.Served))
        {
            throw new InvalidDataException(
                "Disk and served TUF state differ before Rekor shard " +
                "rotation.");
        }
        var active = SigstoreRekorShard.ReadActiveMaterial(
            resource.StatePath);
        var tlogEntries = SigstoreRekorShard.ReadTlogEntries(
            resource.StatePath);
        if (!tlogEntries.Any(
                entry => entry.PublicKeySha256 == active.PublicKeySha256))
        {
            throw new InvalidDataException(
                "TrustedRoot does not contain the running Rekor shard.");
        }
        if (tlogEntries.Count != 1
            || tlogEntries[0].BaseUrl != RekorPrimaryUrl)
        {
            throw new InvalidDataException(
                "TrustedRoot Rekor routing does not match the canonical " +
                "single-shard state.");
        }

        var fulcioStatus = await runtime.ReadFulcioStatusAsync(
            cancellationToken);
        var (oldArtifact, oldTlogEntry) =
            await WaitForArtifactWithTlogEntryAsync(
                0,
                fulcioStatus.ActiveRootSha256,
                cancellationToken);
        if (oldTlogEntry.LogIdSha256 != active.PublicKeySha256)
        {
            throw new InvalidDataException(
                "The retained artifact was not logged by the active " +
                "Rekor shard.");
        }

        var operationId = Guid.NewGuid().ToString("N");
        var operation = new RekorShardRotationCommandJournal(
            SchemaVersion: 1,
            OperationId: operationId,
            Status: RekorRequestedStatus,
            StartedAtUtc: DateTimeOffset.UtcNow,
            CompletedAtUtc: null,
            TrustDomainId: starting.Tuf.Trust.TrustDomainId,
            StartingGeneration: starting.Tuf.Trust.Generation,
            StartingGenerationId: starting.Tuf.Trust.GenerationId,
            StartingGenerationManifestSha256:
                starting.Tuf.Trust.GenerationManifestSha256,
            StartingRekorPublicKeySha256: active.PublicKeySha256,
            PriorShardId: active.ShardId,
            PriorShardUrl: RekorPrimaryUrl,
            StartingSnapshot: starting,
            PrimaryResourceId: primary.ResourceId,
            PrimaryContainerId: primary.ContainerId!,
            PrimaryStartTimeUtc: primary.StartTimeUtc,
            ProtectedResources: CaptureRekorProtectedResources(),
            FulcioRootSha256: fulcioStatus.ActiveRootSha256,
            OldArtifact: oldArtifact,
            OldArtifactLogIdSha256: oldTlogEntry.LogIdSha256,
            OldArtifactLogIndex: oldTlogEntry.LogIndex,
            CandidatePublicKeySha256: null,
            CandidateLogId: null,
            CandidateShardId: null,
            CandidateStateId: null,
            CandidateCreatedAtUtc: null,
            SecondaryResourceId: null,
            SecondaryContainerId: null,
            SecondaryStartTimeUtc: null,
            SecondaryCheckpoint: null,
            WorkerCompletion: null,
            Clients: [],
            ClientsConvergedAtUtc: null,
            NewArtifact: null,
            NewArtifactLogIdSha256: null,
            NewArtifactLogIndex: null,
            SecondaryActivatedAtUtc: null);
        WriteRekorShardRotationJournal(resource.StatePath, operation);
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateRekorShardCommand,
            "requested",
            "Rekor Shard Recovery Pending",
            "The durable retained-artifact proof is captured; candidate " +
            "generation or replay must complete before other trust " +
            "mutations.");
        return operation;
    }

    /// <summary>
    /// Captures every required resource except the six clients and the
    /// primary Rekor server itself. The primary is intentionally excluded
    /// because it is marked historical (moved out of the required set)
    /// once the secondary shard is activated; its identity is instead
    /// tracked and re-verified directly via
    /// <see cref="ValidatePrimaryRekorServerUnchanged"/>, which works
    /// whether the primary is currently required or historical.
    /// </summary>
    private IReadOnlyList<SigstoreResourceInstanceSnapshot>
        CaptureRekorProtectedResources()
    {
        var excluded = resource.GetRegistrations().Clients
            .Select(client => client.Resource.Name)
            .ToHashSet(StringComparer.Ordinal);
        excluded.Add(resource.Components.RekorServer.Resource.Name);
        return resource.GetRegistrations().RequiredResources
            .Where(required => !excluded.Contains(required.Name))
            .OrderBy(required => required.Name, StringComparer.Ordinal)
            .Select(
                required =>
                {
                    var snapshot = runtime.GetRequiredSnapshot(required);
                    if (!IsRunningHealthy(snapshot)
                        || !HasContainerIdentity(snapshot))
                    {
                        throw new InvalidOperationException(
                            $"Protected resource '{required.Name}' is " +
                            $"{Describe(snapshot)}.");
                    }
                    return snapshot;
                })
            .ToArray();
    }

    /// <summary>
    /// Directly proves the primary Rekor server's container identity and
    /// health have not changed since the rotation started, independent of
    /// whether it is still a required resource or has since been marked
    /// historical by <c>MarkResourceHistorical</c> (which only changes
    /// aggregate-health bookkeeping, never the container itself). This
    /// check must always pass — the primary Rekor server is never
    /// restarted or mutated by this rotation, before or after commit.
    /// </summary>
    private bool ValidatePrimaryRekorServerUnchanged(
        OperationExecution execution,
        RekorShardRotationCommandJournal operation,
        string phase)
    {
        var current = runtime.GetRequiredSnapshot(
            resource.Components.RekorServer.Resource);
        return execution.Check(
            "primary-rekor-server-not-restarted",
            current.ContainerId == operation.PrimaryContainerId
                && current.StartTimeUtc == operation.PrimaryStartTimeUtc
                && IsRunningHealthy(current),
            $"container {operation.PrimaryContainerId}, started " +
                $"{operation.PrimaryStartTimeUtc:O}, Running/Healthy",
            Describe(current),
            phase,
            resource.Components.RekorServer.Resource.Name);
    }

    private void PrepareSecondaryShardData(
        RekorShardRotationCommandJournal operation)
    {
        var dataPath = Path.Combine(
            resource.StatePath,
            "data",
            "rekor-shards",
            "secondary");
        Directory.CreateDirectory(dataPath);
        var stateId = operation.CandidateStateId
            ?? throw new InvalidDataException(
                "The Rekor rotation candidate state ID is missing.");
        WriteCreateNewBytes(
            Path.Combine(dataPath, "bootstrap-state"),
            Encoding.UTF8.GetBytes(stateId));

        var metadata = new RekorShardMetadataFile(
            SchemaVersion: 1,
            OperationId: operation.OperationId,
            TrustDomainId: operation.TrustDomainId,
            ShardId: operation.CandidateShardId
                ?? throw new InvalidDataException(
                    "The Rekor rotation candidate shard ID is missing."),
            Slot: "secondary",
            BaseUrl: RekorSecondaryUrl,
            Origin: RekorSecondaryOrigin,
            PublicKeySha256: operation.CandidatePublicKeySha256
                ?? throw new InvalidDataException(
                    "The Rekor rotation candidate public key is " +
                    "missing."),
            LogIdSha256: operation.CandidateLogId
                ?? throw new InvalidDataException(
                    "The Rekor rotation candidate log ID is missing."),
            StateId: stateId,
            DataPath: RekorSecondaryDataRelativePath,
            ResourceName:
                resource.Components.RekorServerSecondary.Resource.Name,
            CreatedAtUtc: operation.CandidateCreatedAtUtc
                ?? throw new InvalidDataException(
                    "The Rekor rotation candidate creation time is " +
                    "missing."));
        var metadataPath = Path.Combine(dataPath, "shard.json");
        if (File.Exists(metadataPath))
        {
            var existing = JsonSerializer.Deserialize<
                RekorShardMetadataFile>(
                    File.ReadAllText(metadataPath),
                    JsonOptions);
            if (existing != metadata)
            {
                throw new InvalidDataException(
                    "The secondary Rekor shard metadata changed during " +
                    "replay.");
            }
            return;
        }
        WriteCreateNewJson(metadataPath, metadata);
    }

    /// <summary>
    /// Probes the secondary Rekor shard's health without needing to set a
    /// custom <c>Host</c> header: nginx routes primarily by <c>Host</c> to
    /// <c>rekor-secondary-sigstore.dev.localhost</c> (the canonical
    /// secondary origin), but the shared default gateway server also
    /// exposes <c>/shards/secondary/healthz</c> as an internal path-based
    /// probe alias to the same backend, which is what hosting code uses
    /// here purely for convenience.
    /// </summary>
    private async Task ProbeSecondaryHealthThroughGatewayAsync(
        CancellationToken cancellationToken)
    {
        var gateway = await resource.Components.Rekor
            .GetEndpoint("http")
            .GetValueAsync(cancellationToken)
            ?? throw new InvalidOperationException(
                "The Rekor gateway endpoint is not allocated.");
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(15)
        };
        using var response = await client.GetAsync(
            new Uri(
                new Uri(gateway, UriKind.Absolute),
                RekorSecondaryProbeAliasPathPrefix + "healthz"),
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidDataException(
                "The secondary Rekor shard health route returned HTTP " +
                $"{(int)response.StatusCode}.");
        }
    }

    /// <summary>
    /// Probes the secondary Rekor shard's signed checkpoint through the
    /// shared gateway's <c>/shards/secondary/checkpoint</c> path-based
    /// probe alias (see <see cref="ProbeSecondaryHealthThroughGatewayAsync"/>).
    /// The checkpoint's own origin line must still equal the canonical
    /// origin <c>rekor-secondary-sigstore.dev.localhost</c> — the
    /// secondary rekor-server is started with exactly that
    /// <c>--hostname</c>, independent of which route hosting code used to
    /// fetch the checkpoint bytes.
    /// </summary>
    private async Task<SigstoreRekorCheckpointEvidence>
        ProbeSecondaryCheckpointThroughGatewayAsync(
            byte[] signerPublicKeySpki,
            CancellationToken cancellationToken)
    {
        var gateway = await resource.Components.Rekor
            .GetEndpoint("http")
            .GetValueAsync(cancellationToken)
            ?? throw new InvalidOperationException(
                "The Rekor gateway endpoint is not allocated.");
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(15)
        };
        using var response = await client.GetAsync(
            new Uri(
                new Uri(gateway, UriKind.Absolute),
                RekorSecondaryProbeAliasPathPrefix + "checkpoint"),
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidDataException(
                "The secondary Rekor shard checkpoint route returned " +
                $"HTTP {(int)response.StatusCode}.");
        }
        var bytes = await response.Content.ReadAsByteArrayAsync(
            cancellationToken);
        return SigstoreRekorShard.ReadAndVerifyCheckpoint(
            bytes,
            RekorSecondaryOrigin,
            signerPublicKeySpki);
    }

    private async Task<(
        SigstoreArtifactEvidence Artifact,
        SigstoreRekorArtifactLogEntry TlogEntry)>
        WaitForArtifactWithTlogEntryAsync(
            long minimumExclusiveId,
            string expectedFulcioRootSha256,
            CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow.AddMinutes(5);
        Exception? last = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var artifact = await runtime.FindArtifactAsync(
                    minimumExclusiveId,
                    expectedFulcioRootSha256,
                    cancellationToken);
                var tlogEntry = await ReadArtifactRekorTlogEntryAsync(
                    artifact.ArtifactId,
                    cancellationToken);
                return (artifact, tlogEntry);
            }
            catch (InvalidDataException exception)
            {
                last = exception;
            }
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
        }
        throw new InvalidDataException(
            "Timed out waiting for a sealed artifact with Rekor " +
            $"transparency-log evidence: {last?.Message}");
    }

    private async Task<SigstoreRekorArtifactLogEntry>
        ReadArtifactRekorTlogEntryAsync(
            long artifactId,
            CancellationToken cancellationToken)
    {
        var endpoint = await resource.ArtifactStoreEndpoint.GetValueAsync(
            cancellationToken)
            ?? throw new InvalidOperationException(
                "The artifact-store endpoint is not allocated.");
        var baseUri = new Uri(
            endpoint.EndsWith('/') ? endpoint : endpoint + "/",
            UriKind.Absolute);
        using var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
        using var response = await client.GetAsync(
            new Uri(baseUri, $"artifacts/{artifactId}/signature"),
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidDataException(
                $"Artifact {artifactId} signature endpoint returned " +
                $"HTTP {(int)response.StatusCode}.");
        }
        var bytes = await response.Content.ReadAsByteArrayAsync(
            cancellationToken);
        return SigstoreRekorShard.ReadArtifactTlogEntry(bytes);
    }

    private static string ReadGenerationManifestSha256(
        string statePath,
        string generationId) =>
        Hash(
            File.ReadAllBytes(
                Path.Combine(
                    statePath,
                    "generations",
                    generationId,
                    "manifest.json")));

    private static string RekorRotationCandidatePath(
        string statePath,
        string operationId) =>
        Path.Combine(
            statePath,
            "rekor-shard-rotation",
            operationId,
            "candidate");

    private static string RekorShardHostingJournalPath(
        string statePath,
        string operationId) =>
        Path.Combine(
            statePath,
            "rekor-shard-rotation",
            operationId,
            "hosting-state.json");

    private static RekorShardRotationCommandJournal?
        LoadIncompleteRekorShardRotation(string statePath)
    {
        var journals = SigstoreRekorShard.ReadRotationJournals(statePath)
            .Where(journal => journal.Status != RekorCompletedStatus)
            .ToArray();
        return journals.Length switch
        {
            0 => null,
            1 => journals[0],
            _ => throw new InvalidDataException(
                "Multiple incomplete Rekor shard rotation operations " +
                "exist.")
        };
    }

    private static void WriteRekorShardRotationJournal(
        string statePath,
        RekorShardRotationCommandJournal operation)
    {
        var path = RekorShardHostingJournalPath(
            statePath,
            operation.OperationId);
        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidDataException(
                $"Path '{path}' has no parent directory.");
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(
            directory,
            $".hosting-state.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
        var data = JsonSerializer.Serialize(operation, JsonOptions) + "\n";
        using (var stream = new FileStream(
            temporary,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough))
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    temporary,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            var bytes = Encoding.UTF8.GetBytes(data);
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, path, overwrite: true);
        SyncParentDirectory(path);
    }

    private static void WriteRekorShardRotationRequest(
        string statePath,
        RekorShardRotationCommandJournal operation)
    {
        var request = new RekorShardRotationWorkerRequest(
            SchemaVersion: 1,
            OperationId: operation.OperationId,
            TrustDomainId: operation.TrustDomainId,
            StartingGeneration: operation.StartingGeneration,
            StartingGenerationId: operation.StartingGenerationId,
            StartingGenerationManifestSha256:
                operation.StartingGenerationManifestSha256,
            StartingRekorPublicKeySha256:
                operation.StartingRekorPublicKeySha256,
            PriorShardId: operation.PriorShardId,
            PriorShardUrl: operation.PriorShardUrl,
            CandidateShardId: operation.CandidateShardId
                ?? throw new InvalidDataException(
                    "The Rekor rotation candidate shard ID is missing."),
            CandidateShardUrl: RekorSecondaryUrl,
            CandidateOrigin: RekorSecondaryOrigin,
            CandidatePublicKeySha256: operation.CandidatePublicKeySha256
                ?? throw new InvalidDataException(
                    "The Rekor rotation candidate public key is " +
                    "missing."),
            CandidateStateId: operation.CandidateStateId
                ?? throw new InvalidDataException(
                    "The Rekor rotation candidate state ID is missing."),
            CandidateCreatedAtUtc: operation.CandidateCreatedAtUtc
                ?? throw new InvalidDataException(
                    "The Rekor rotation candidate creation time is " +
                    "missing."));
        var path = Path.Combine(statePath, "rotate-rekor-shard.request");
        if (File.Exists(path))
        {
            var existing = JsonSerializer.Deserialize<
                RekorShardRotationWorkerRequest>(
                    File.ReadAllText(path),
                    JsonOptions);
            if (existing != request)
            {
                throw new InvalidDataException(
                    "The surviving Rekor shard rotation worker request " +
                    "belongs to another operation or candidate.");
            }
            return;
        }
        WriteCreateNewJson(path, request);
    }

    private static RekorShardRotationWorkerCompletion?
        ReadRekorShardRotationWorkerCompletion(string statePath)
    {
        var path = Path.Combine(statePath, "rotate-rekor-shard.completed");
        if (!File.Exists(path))
        {
            return null;
        }
        var completion = JsonSerializer.Deserialize<
            RekorShardRotationWorkerCompletion>(
                File.ReadAllText(path),
                JsonOptions)
            ?? throw new InvalidDataException(
                "The Rekor shard rotation worker completion is empty.");
        if (completion.SchemaVersion != 1
            || !Guid.TryParseExact(completion.OperationId, "N", out _)
            || completion.OperationId.Any(char.IsUpper)
            || completion.PriorGeneration < 1
            || completion.NewGeneration != completion.PriorGeneration + 1
            || completion.PriorGenerationId
                != $"generation-{completion.PriorGeneration:D8}"
            || completion.NewGenerationId
                != $"generation-{completion.NewGeneration:D8}"
            || !IsLowerHexSha256(completion.PriorGenerationManifestSha256)
            || !IsLowerHexSha256(completion.GenerationManifestSha256)
            || !IsLowerHexSha256(completion.PriorPublicKeySha256)
            || !IsLowerHexSha256(completion.NewPublicKeySha256)
            || completion.PriorShardId
                != $"sha256-{completion.PriorPublicKeySha256}"
            || completion.NewShardId
                != $"sha256-{completion.NewPublicKeySha256}"
            || completion.PriorBaseUrl != RekorPrimaryUrl
            || completion.NewBaseUrl != RekorSecondaryUrl
            || string.IsNullOrWhiteSpace(completion.PriorStateId)
            || string.IsNullOrWhiteSpace(completion.NewStateId)
            || string.IsNullOrWhiteSpace(completion.PublicationId)
            || !IsLowerHexSha256(completion.PublicationManifestSha256)
            || !IsLowerHexSha256(completion.TrustedRootSha256)
            || !IsLowerHexSha256(completion.SigningConfigSha256)
            || completion.NewTrustedRootTlogCount
                != completion.PriorTrustedRootTlogCount + 1
            || completion.ActiveSigningConfigUrl != RekorSecondaryUrl)
        {
            throw new InvalidDataException(
                "The Rekor shard rotation worker completion is invalid.");
        }
        return completion;
    }

    private static void ValidateRekorShardRotationCompletion(
        RekorShardRotationWorkerCompletion completion,
        RekorShardRotationCommandJournal operation,
        SigstoreOperationSnapshot after)
    {
        if (completion.OperationId != operation.OperationId
            || completion.TrustDomainId != operation.TrustDomainId
            || completion.PriorGeneration != operation.StartingGeneration
            || completion.PriorGenerationId
                != operation.StartingGenerationId
            || completion.PriorGenerationManifestSha256
                != operation.StartingGenerationManifestSha256
            || completion.PriorPublicKeySha256
                != operation.StartingRekorPublicKeySha256
            || completion.PriorShardId != operation.PriorShardId
            || completion.PriorBaseUrl != operation.PriorShardUrl
            || completion.NewGeneration
                != operation.StartingGeneration + 1
            || completion.NewGenerationId != after.Tuf.Trust.GenerationId
            || completion.GenerationManifestSha256
                != after.Tuf.Trust.GenerationManifestSha256
            || completion.NewPublicKeySha256
                != operation.CandidatePublicKeySha256
            || completion.NewShardId != operation.CandidateShardId
            || completion.NewBaseUrl != RekorSecondaryUrl
            || completion.NewStateId != operation.CandidateStateId
            || completion.PublicationId != after.Tuf.Trust.PublicationId
            || completion.PublicationManifestSha256
                != after.Tuf.Trust.PublicationManifestSha256
            || completion.TrustedRootSha256
                != after.Tuf.Trust.TrustedRootSha256
            || completion.SigningConfigSha256
                != after.Tuf.Trust.SigningConfigSha256
            || completion.ActiveSigningConfigUrl != RekorSecondaryUrl)
        {
            throw new InvalidDataException(
                "The Rekor shard rotation worker completion does not " +
                "match the durable operation or committed trust state.");
        }
    }

    private static void ValidateRekorShardPublicationPostconditions(
        OperationExecution execution,
        RekorShardRotationCommandJournal operation,
        SigstoreOperationSnapshot before,
        SigstoreOperationSnapshot after,
        IReadOnlyList<SigstoreRekorTlogEntry> tlogEntries,
        RekorShardCatalog catalog)
    {
        var completion = operation.WorkerCompletion
            ?? throw new InvalidDataException(
                "Rekor shard rotation worker completion is missing.");
        execution.Check(
            "generation-advanced",
            after.Tuf.Trust.Generation
                    == before.Tuf.Trust.Generation + 1
                && after.Tuf.Trust.GenerationId
                    != before.Tuf.Trust.GenerationId,
            $"generation {before.Tuf.Trust.Generation + 1}",
            $"generation {after.Tuf.Trust.Generation}",
            "worker-postconditions",
            "tuf-bootstrap");
        CheckEqual(
            execution,
            "trust-domain-unchanged",
            before.Tuf.Trust.TrustDomainId,
            after.Tuf.Trust.TrustDomainId);
        CheckEqual(
            execution,
            "tuf-root-unchanged",
            before.Tuf.Metadata.Root,
            after.Tuf.Metadata.Root);
        CheckEqual(
            execution,
            "bootstrap-root-unchanged",
            before.Tuf.BootstrapRootSha256,
            after.Tuf.BootstrapRootSha256);
        execution.Check(
            "signing-config-changed-exclusively",
            before.Tuf.Trust.SigningConfigSha256
                != after.Tuf.Trust.SigningConfigSha256,
            "a changed SigningConfig hash routing exclusively to the " +
                "secondary shard",
            after.Tuf.Trust.SigningConfigSha256,
            "worker-postconditions",
            "tuf-bootstrap");
        execution.Check(
            "trusted-root-additive-change",
            before.Tuf.Trust.TrustedRootSha256
                != after.Tuf.Trust.TrustedRootSha256,
            "changed TrustedRoot hash",
            after.Tuf.Trust.TrustedRootSha256,
            "worker-postconditions",
            "tuf-bootstrap");
        execution.Check(
            "publication-advanced-with-prior-history",
            after.Tuf.Trust.PublicationId
                    != before.Tuf.Trust.PublicationId
                && after.Tuf.PreviousPublicationId
                    == before.Tuf.Trust.PublicationId
                && after.Tuf.PreviousPublicationManifestSha256
                    == before.Tuf.Trust.PublicationManifestSha256,
            $"{before.Tuf.Trust.PublicationId}/" +
                before.Tuf.Trust.PublicationManifestSha256,
            $"{after.Tuf.Trust.PublicationId}/" +
                $"{after.Tuf.Trust.PublicationManifestSha256} previous=" +
                $"{after.Tuf.PreviousPublicationId}/" +
                after.Tuf.PreviousPublicationManifestSha256,
            "worker-postconditions",
            "tuf-bootstrap");
        CheckAdvanced(
            execution,
            "targets-advanced",
            before.Tuf.Metadata.Targets,
            after.Tuf.Metadata.Targets);
        CheckAdvanced(
            execution,
            "snapshot-advanced",
            before.Tuf.Metadata.Snapshot,
            after.Tuf.Metadata.Snapshot);
        CheckAdvanced(
            execution,
            "timestamp-metadata-advanced",
            before.Tuf.Metadata.Timestamp,
            after.Tuf.Metadata.Timestamp);

        var priorEntry = tlogEntries.SingleOrDefault(
            entry => entry.PublicKeySha256
                    == operation.StartingRekorPublicKeySha256
                && entry.BaseUrl == operation.PriorShardUrl);
        execution.Check(
            "old-rekor-trust-preserved",
            priorEntry is not null,
            $"{operation.PriorShardUrl}/" +
                operation.StartingRekorPublicKeySha256,
            priorEntry is null
                ? "missing"
                : $"{priorEntry.BaseUrl}/{priorEntry.PublicKeySha256}",
            "worker-postconditions",
            "trusted_root.json");
        var newEntry = tlogEntries.Count > 0
            ? tlogEntries[^1]
            : null;
        execution.Check(
            "new-rekor-trust-appended",
            tlogEntries.Count == completion.NewTrustedRootTlogCount
                && completion.NewTrustedRootTlogCount
                    == completion.PriorTrustedRootTlogCount + 1
                && newEntry is not null
                && newEntry.PublicKeySha256
                    == completion.NewPublicKeySha256
                && newEntry.BaseUrl == RekorSecondaryUrl,
            $"{completion.PriorTrustedRootTlogCount + 1} entries ending " +
                "in the new shard",
            $"{tlogEntries.Count} entries ending in " +
                $"{newEntry?.BaseUrl}/{newEntry?.PublicKeySha256}",
            "worker-postconditions",
            "trusted_root.json");
        execution.Check(
            "shard-catalog-switched",
            catalog.Shards.Count == 2
                && catalog.ActiveShardId == operation.CandidateShardId
                && catalog.Shards[0].Status == "historical"
                && catalog.Shards[1].Status == "active"
                && catalog.Shards[1].PublicKeySha256
                    == operation.CandidatePublicKeySha256
                && catalog.Shards[1].StateId == operation.CandidateStateId,
            $"two shards active on {operation.CandidateShardId}",
            $"{catalog.Shards.Count} shards active on " +
                catalog.ActiveShardId,
            "worker-postconditions",
            "rekor-shard-catalog");
        execution.Check(
            "disk-served-after-rekor-publish",
            MatchesServed(after.Tuf, after.Served),
            Describe(after.Tuf),
            Describe(after.Served),
            "worker-postconditions",
            after.TufServer.Resource);
        execution.Check(
            "tuf-server-not-restarted",
            SameInstance(before.TufServer, after.TufServer)
                && IsRunningHealthy(after.TufServer),
            Describe(before.TufServer),
            Describe(after.TufServer),
            "worker-postconditions",
            after.TufServer.Resource);
    }

    private static IReadOnlyList<RekorShardClientConvergence>
        UpsertRekorClientConvergence(
            IReadOnlyList<RekorShardClientConvergence> existing,
            RekorShardClientConvergence current) =>
        existing
            .Where(item => item.Resource != current.Resource)
            .Append(current)
            .OrderBy(item => item.Resource, StringComparer.Ordinal)
            .ToArray();

    private static RekorShardRotationEvidence
        BuildRekorShardRotationEvidence(
            RekorShardRotationCommandJournal operation,
            bool recovered) =>
        new(
            operation.OperationId,
            operation.Status,
            recovered,
            operation.StartingGeneration,
            operation.StartingGenerationId,
            operation.WorkerCompletion?.NewGeneration,
            operation.WorkerCompletion?.NewGenerationId,
            operation.PriorShardId,
            operation.PriorShardUrl,
            operation.CandidateShardId,
            operation.CandidateShardId is null ? null : RekorSecondaryUrl,
            operation.StartingRekorPublicKeySha256,
            operation.CandidatePublicKeySha256,
            operation.CandidateStateId,
            operation.SecondaryCheckpoint,
            operation.WorkerCompletion?.PublicationId,
            operation.WorkerCompletion?.GenerationManifestSha256,
            operation.WorkerCompletion?.PriorTrustedRootTlogCount,
            operation.WorkerCompletion?.NewTrustedRootTlogCount,
            operation.OldArtifact.ArtifactId,
            operation.OldArtifactLogIdSha256,
            operation.OldArtifactLogIndex,
            operation.NewArtifact?.ArtifactId,
            operation.NewArtifactLogIdSha256,
            operation.NewArtifactLogIndex,
            operation.Clients);

    private static ExecuteCommandResult CreateRekorShardResult(
        OperationExecution execution,
        bool success,
        string message,
        RekorShardRotationEvidence? evidence)
    {
        var startedAtUtc = execution.Progress.Count > 0
            ? execution.Progress[0].ObservedAtUtc
            : DateTimeOffset.UtcNow;
        var result = new RekorShardRotationOperationResult(
            1,
            SigstoreOperationCommand.RotateRekorShardCommand,
            success,
            execution.Phase,
            message,
            startedAtUtc,
            DateTimeOffset.UtcNow,
            execution.Progress,
            execution.Before,
            execution.After,
            execution.Resources,
            execution.Checks,
            execution.CommittedStatePreserved,
            execution.Errors,
            evidence);
        var json = JsonSerializer.Serialize(result, JsonOptions);
        return new ExecuteCommandResult
        {
            Success = success,
            Message = message,
            Data = new CommandResultData
            {
                Value = json,
                Format = CommandResultFormat.Json,
                DisplayImmediately = true
            }
        };
    }
}

internal sealed record RekorShardRotationWorkerRequest(
    int SchemaVersion,
    string OperationId,
    string TrustDomainId,
    int StartingGeneration,
    string StartingGenerationId,
    string StartingGenerationManifestSha256,
    string StartingRekorPublicKeySha256,
    string PriorShardId,
    string PriorShardUrl,
    string CandidateShardId,
    string CandidateShardUrl,
    string CandidateOrigin,
    string CandidatePublicKeySha256,
    string CandidateStateId,
    DateTimeOffset CandidateCreatedAtUtc);

internal sealed record RekorShardRotationWorkerCompletion(
    int SchemaVersion,
    string OperationId,
    string TrustDomainId,
    DateTimeOffset CompletedAtUtc,
    int PriorGeneration,
    string PriorGenerationId,
    string PriorGenerationManifestSha256,
    string PriorPublicKeySha256,
    string PriorShardId,
    string PriorBaseUrl,
    string PriorStateId,
    int NewGeneration,
    string NewGenerationId,
    string GenerationManifestSha256,
    string NewPublicKeySha256,
    string NewShardId,
    string NewBaseUrl,
    string NewStateId,
    string PublicationId,
    string PublicationManifestSha256,
    string TrustedRootSha256,
    string SigningConfigSha256,
    int PriorTrustedRootTlogCount,
    int NewTrustedRootTlogCount,
    string ActiveSigningConfigUrl,
    string Action);

internal sealed record RekorShardMetadataFile(
    int SchemaVersion,
    string OperationId,
    string TrustDomainId,
    string ShardId,
    string Slot,
    string BaseUrl,
    string Origin,
    string PublicKeySha256,
    string LogIdSha256,
    string StateId,
    string DataPath,
    string ResourceName,
    DateTimeOffset CreatedAtUtc);

internal sealed record RekorShardClientConvergence(
    string Resource,
    string ContainerId,
    DateTime? StartTimeUtc,
    DateTimeOffset ConvergedAtUtc,
    SigstoreClientTrustStatus Status);

internal sealed record RekorShardRotationCommandJournal(
    int SchemaVersion,
    string OperationId,
    string Status,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset? CompletedAtUtc,
    string TrustDomainId,
    int StartingGeneration,
    string StartingGenerationId,
    string StartingGenerationManifestSha256,
    string StartingRekorPublicKeySha256,
    string PriorShardId,
    string PriorShardUrl,
    SigstoreOperationSnapshot StartingSnapshot,
    string PrimaryResourceId,
    string PrimaryContainerId,
    DateTime? PrimaryStartTimeUtc,
    IReadOnlyList<SigstoreResourceInstanceSnapshot> ProtectedResources,
    string FulcioRootSha256,
    SigstoreArtifactEvidence OldArtifact,
    string OldArtifactLogIdSha256,
    long OldArtifactLogIndex,
    string? CandidatePublicKeySha256,
    string? CandidateLogId,
    string? CandidateShardId,
    string? CandidateStateId,
    DateTimeOffset? CandidateCreatedAtUtc,
    string? SecondaryResourceId,
    string? SecondaryContainerId,
    DateTime? SecondaryStartTimeUtc,
    SigstoreRekorCheckpointEvidence? SecondaryCheckpoint,
    RekorShardRotationWorkerCompletion? WorkerCompletion,
    IReadOnlyList<RekorShardClientConvergence> Clients,
    DateTimeOffset? ClientsConvergedAtUtc,
    SigstoreArtifactEvidence? NewArtifact,
    string? NewArtifactLogIdSha256,
    long? NewArtifactLogIndex,
    DateTimeOffset? SecondaryActivatedAtUtc);

internal sealed record RekorShardRotationEvidence(
    string OperationId,
    string Status,
    bool Recovered,
    int StartingGeneration,
    string StartingGenerationId,
    int? NewGeneration,
    string? NewGenerationId,
    string PriorShardId,
    string PriorShardUrl,
    string? NewShardId,
    string? NewShardUrl,
    string StartingRekorPublicKeySha256,
    string? CandidatePublicKeySha256,
    string? SecondaryStateId,
    SigstoreRekorCheckpointEvidence? SecondaryCheckpoint,
    string? PublicationId,
    string? GenerationManifestSha256,
    int? PriorTrustedRootTlogCount,
    int? NewTrustedRootTlogCount,
    long OldArtifactId,
    string OldArtifactLogIdSha256,
    long OldArtifactLogIndex,
    long? NewArtifactId,
    string? NewArtifactLogIdSha256,
    long? NewArtifactLogIndex,
    IReadOnlyList<RekorShardClientConvergence> Clients);

internal sealed record RekorShardRotationOperationResult(
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
    IReadOnlyList<SigstoreOperationError> Errors,
    RekorShardRotationEvidence? RekorShardRotation);
