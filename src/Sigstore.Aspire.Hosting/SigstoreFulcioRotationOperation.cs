using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Sigstore.Bootstrap;

namespace Aspire.Hosting.ApplicationModel;

internal sealed partial class SigstoreOperationExecutor
{
    private const string FulcioStatusRequested = "requested";
    private const string FulcioStatusCandidateGenerated =
        "candidate-generated";
    private const string FulcioStatusWorkerCommitted =
        "worker-committed";
    private const string FulcioStatusClientsConverged =
        "clients-converged";
    private const string FulcioStatusTesseractRestarted =
        "tesseract-restarted";
    private const string FulcioStatusOldCaProved = "old-ca-proved";
    private const string FulcioStatusRuntimeActivated =
        "runtime-activated";
    private const string FulcioStatusFulcioRestarted =
        "fulcio-restarted";
    private const string FulcioStatusNewCaProved = "new-ca-proved";
    private const string FulcioStatusCompleted = "completed";

    public async Task<ExecuteCommandResult> ExecuteRotateFulcioCaAsync(
        CancellationToken requestCancellationToken)
    {
        requestCancellationToken.ThrowIfCancellationRequested();
        if (CreateRecoveryBlockResult(
                SigstoreOperationCommand.RotateFulcioCaCommand) is { } blocked)
        {
            return blocked;
        }
        if (!resource.TryBeginOperation(
                SigstoreOperationCommand.RotateFulcioCaCommand,
                "Rotating Fulcio CA",
                out var lease,
                out var active))
        {
            return CreateContentionResult(
                SigstoreOperationCommand.RotateFulcioCaCommand,
                active!);
        }

        var execution = new OperationExecution(
            resource,
            runtime,
            logger,
            lease!,
            total: 26);
        try
        {
            return await ExecuteRotateFulcioCaCoreAsync(
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
            return execution.Failure(
                $"{SigstoreOperationCommand.RotateFulcioCaCommand} failed " +
                $"during {execution.Phase}.");
        }
        finally
        {
            lease!.Dispose();
            await runtime.PublishParentStateAsync(resource);
        }
    }

    private async Task<ExecuteCommandResult> ExecuteRotateFulcioCaCoreAsync(
        OperationExecution execution,
        CancellationToken requestCancellationToken)
    {
        await execution.ReportAsync(
            "preflight",
            0,
            "Validating durable trust, resources, Fulcio, Tesseract, and CT state.");

        FulcioRotationCommandJournal operation;
        SigstoreOperationSnapshot before;
        SigstoreResourceInstanceSnapshot workerBefore;
        var startWorker = false;
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-rotate-fulcio-ca-preflight"))
        {
            requestCancellationToken.ThrowIfCancellationRequested();
            workerBefore = runtime.GetRequiredSnapshot(
                resource.Components.TufBootstrap.Resource);
            var fulcioBefore = runtime.GetRequiredSnapshot(
                resource.Components.Fulcio.Resource);
            // A Fulcio CA rotation extends the accepted-root bundle of the
            // certificate-transparency shard that is currently accepting
            // submissions and restarts exactly that shard. Before a CT log
            // shard rotation that is the primary shard; afterwards it is
            // the secondary, and the historical primary stays frozen,
            // running and never restarted so its append-only tiles remain
            // verifiable.
            if (!ValidateCtShardRotationSettled(execution))
            {
                return execution.Failure(
                    "A certificate-transparency log shard rotation is in " +
                    "flight; the Fulcio certificate authority cannot be " +
                    "rotated until it completes.");
            }
            var ctShard = ResolveActiveCtShardResource();
            var tesseractBefore = runtime.GetRequiredSnapshot(ctShard);
            if (!execution.Check(
                    "worker-restartable",
                    IsTerminal(workerBefore)
                        && HasContainerIdentity(workerBefore),
                    "terminal with container identity",
                    Describe(workerBefore),
                    "preflight",
                    workerBefore.Resource)
                || !execution.Check(
                    "fulcio-running",
                    IsRunningHealthy(fulcioBefore)
                        && HasContainerIdentity(fulcioBefore),
                    "Running/Healthy with container identity",
                    Describe(fulcioBefore),
                    "preflight",
                    fulcioBefore.Resource)
                || !execution.Check(
                    "tesseract-running",
                    IsRunningHealthy(tesseractBefore)
                        && HasContainerIdentity(tesseractBefore),
                    "Running/Healthy with container identity",
                    Describe(tesseractBefore),
                    "preflight",
                    tesseractBefore.Resource))
            {
                return execution.Failure(
                    "Fulcio rotation resource preconditions are not satisfied.");
            }

            var incomplete = LoadIncompleteFulcioRotation(
                resource.StatePath);
            if (incomplete is null
                && !await ValidatePreconditionsAsync(
                    execution,
                    requestCancellationToken))
            {
                return execution.Failure(
                    "Fulcio rotation trust preconditions are not satisfied.");
            }
            operation = incomplete
                ?? await CreateFulcioRotationOperationAsync(
                    fulcioBefore,
                    tesseractBefore,
                    requestCancellationToken);
            before = operation.StartingSnapshot;
            execution.Before = before;
            execution.FulcioRotation = CreateFulcioRotationResult(
                operation,
                recovered: incomplete is not null);

            ValidateFulcioJournalStartingState(
                operation,
                execution);
            if (execution.HasFailures)
            {
                return execution.Failure(
                    "Fulcio rotation recovery validation failed.");
            }
            if (!ValidateProtectedResources(
                    execution,
                    operation.ProtectedResources,
                    "preflight"))
            {
                return execution.Failure(
                    "A protected Sigstore service changed during Fulcio rotation.");
            }

            var activeGeneration = ReadActiveFulcioGeneration(
                resource.StatePath);
            if (activeGeneration.Generation
                == operation.StartingGeneration)
            {
                if (activeGeneration.GenerationId
                        != operation.StartingGenerationId
                    || activeGeneration.FulcioRootSha256
                        != operation.StartingFulcioRootSha256
                    || !SameInstance(
                        SnapshotFromJournal(
                            operation.FulcioResourceId,
                            resource.Components.Fulcio.Resource.Name,
                            operation.FulcioContainerId,
                            operation.FulcioStartTimeUtc),
                        fulcioBefore)
                    || !SameInstance(
                        SnapshotFromJournal(
                            operation.TesseractResourceId,
                            ctShard.Name,
                            operation.TesseractContainerId,
                            operation.TesseractStartTimeUtc),
                        tesseractBefore))
                {
                    throw new InvalidDataException(
                        "The old Fulcio issuer or Tesseract instance changed " +
                        "before additive trust publication.");
                }

                await execution.ReportAsync(
                    "generate-candidate",
                    2,
                    "Generating or validating the operation-bound Fulcio CA.");
                var candidate =
                    stateInspector.EnsureFulcioCaRotationCandidate(
                        FulcioCandidatePath(
                            resource.StatePath,
                            operation.OperationId));
                if (operation.CandidateFulcioRootSha256 is not null
                    && operation.CandidateFulcioRootSha256
                        != candidate.RootSha256)
                {
                    throw new InvalidDataException(
                        "The Fulcio CA candidate changed during replay.");
                }
                operation = operation with
                {
                    Status = FulcioStatusCandidateGenerated,
                    CandidateFulcioRootSha256 = candidate.RootSha256
                };
                WriteFulcioRotationJournal(
                    resource.StatePath,
                    operation);
                WriteFulcioWorkerRequest(
                    resource.StatePath,
                    operation);
                startWorker = true;
            }
            else if (activeGeneration.Generation
                    == operation.StartingGeneration + 1
                && activeGeneration.FulcioRotationOperationId
                    == operation.OperationId)
            {
                if (ReadFulcioWorkerCompletion(resource.StatePath) is null)
                {
                    WriteFulcioWorkerRequest(
                        resource.StatePath,
                        operation);
                    startWorker = true;
                }
            }
            else
            {
                throw new InvalidDataException(
                    "The active generation is not safely bound to this " +
                    "Fulcio rotation.");
            }

            resource.SetOperationRecovery(
                SigstoreOperationCommand.RotateFulcioCaCommand,
                startWorker ? "request-written" : operation.Status,
                "Fulcio Recovery Pending",
                "The durable Fulcio rotation must replay to completion before " +
                "other trust mutations.");
        }

        // Once the durable request exists, user cancellation cannot unwind the
        // trust transition or leave activation ordering ambiguous.
        using var critical =
            new CancellationTokenSource(TimeSpan.FromMinutes(30));
        var cancellationToken = critical.Token;
        if (startWorker)
        {
            await execution.ReportAsync(
                "start-worker",
                3,
                "Starting the dedicated additive Fulcio trust worker.");
            var started = await runtime.ExecuteCommandAsync(
                resource.Components.TufBootstrap.Resource,
                KnownResourceCommands.StartCommand,
                cancellationToken);
            if (!started.Success)
            {
                execution.AddError(
                    "start-worker",
                    workerBefore.Resource,
                    null,
                    started.Message
                        ?? "Aspire rejected the TUF worker start.");
                return execution.Failure(
                    "The Fulcio rotation worker could not be started.");
            }
            var workerAfter = await runtime.WaitForSnapshotAsync(
                resource.Components.TufBootstrap.Resource,
                snapshot => IsNewInstance(workerBefore, snapshot)
                    && IsTerminal(snapshot),
                WorkerTimeout,
                cancellationToken);
            execution.Resources.Add(
                CreateLifecycleResult(
                    workerAfter.Resource,
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
                return execution.Failure(
                    "The Fulcio rotation worker did not complete successfully.");
            }
        }

        await execution.ReportAsync(
            "additive-postconditions",
            5,
            "Validating additive TUF trust and immutable generation N+1.");
        SigstoreOperationSnapshot after;
        FulcioRotationWorkerCompletion completion;
        SigstoreFulcioStatus overlapStatus;
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-rotate-fulcio-ca-postconditions"))
        {
            after = await CaptureAsync(cancellationToken);
            execution.After = after;
            completion = ReadFulcioWorkerCompletion(
                resource.StatePath)
                ?? throw new InvalidDataException(
                    "The Fulcio worker completion record is missing.");
            ValidateFulcioWorkerCompletion(
                operation,
                completion,
                after);
            overlapStatus = await runtime.ReadFulcioStatusAsync(
                cancellationToken);
            operation = operation with
            {
                Status = FulcioStatusWorkerCommitted,
                WorkerCompletion = completion
            };
            WriteFulcioRotationJournal(
                resource.StatePath,
                operation);
        }
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateFulcioCaCommand,
            "worker-committed",
            "Fulcio Activation Pending",
            "Additive trust is committed. Clients and Tesseract must converge " +
            "before the Fulcio runtime projection can activate.");
        await runtime.PublishParentStateAsync(resource);

        ValidateFulcioPublicationPostconditions(
            execution,
            operation,
            before,
            after,
            completion,
            overlapStatus);
        if (execution.HasFailures)
        {
            return execution.Failure(
                "Additive Fulcio trust was published, but postconditions failed.");
        }

        var clients = resource.GetRegistrations().Clients
            .OrderBy(
                client => client.Resource.Name,
                StringComparer.Ordinal)
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

        await execution.ReportAsync(
            "restart-clients",
            6,
            "Converging all six clients on additive Fulcio trust.");
        foreach (var (client, index) in clients.Select(
            (client, index) => (client, index)))
        {
            var clientBefore = runtime.GetRequiredSnapshot(
                client.Resource);
            if (!IsRunningHealthy(clientBefore)
                || !HasContainerIdentity(clientBefore))
            {
                throw new InvalidOperationException(
                    $"{client.Resource.Name} is not ready for convergence.");
            }

            SigstoreClientTrustStatus? clientStatus = null;
            try
            {
                clientStatus = await runtime.ReadClientStatusAsync(
                    client,
                    cancellationToken);
            }
            catch (Exception exception)
                when (IsExpectedOperationFailure(exception))
            {
                logger.LogInformation(
                    exception,
                    "{Client} requires restart for additive Fulcio trust.",
                    client.Resource.Name);
            }

            SigstoreResourceInstanceSnapshot clientAfter;
            string lifecycleCommand;
            if (clientStatus is not null
                && MatchesDisk(after.Tuf.Trust, clientStatus))
            {
                clientAfter = clientBefore;
                lifecycleCommand = "already-converged";
            }
            else
            {
                var restart = await runtime.ExecuteCommandAsync(
                    client.Resource,
                    KnownResourceCommands.RestartCommand,
                    cancellationToken);
                if (!restart.Success)
                {
                    throw new InvalidOperationException(
                        restart.Message
                        ?? $"{client.Resource.Name} restart was rejected.");
                }
                clientAfter = await runtime.WaitForSnapshotAsync(
                    client.Resource,
                    snapshot => IsNewInstance(clientBefore, snapshot)
                        && IsRunningHealthy(snapshot),
                    ClientTimeout,
                    cancellationToken);
                clientStatus = await runtime.ReadClientStatusAsync(
                    client,
                    cancellationToken);
                lifecycleCommand = KnownResourceCommands.RestartCommand;
            }
            if (!MatchesDisk(after.Tuf.Trust, clientStatus!))
            {
                throw new InvalidDataException(
                    $"{client.Resource.Name} did not converge on additive " +
                    "Fulcio trust.");
            }
            execution.Resources.Add(
                CreateLifecycleResult(
                    client.Resource.Name,
                    lifecycleCommand,
                    clientBefore,
                    clientAfter,
                    clientStatus));
            operation = operation with
            {
                Clients = UpsertFulcioClient(
                    operation.Clients,
                    new FulcioClientConvergence(
                        client.Resource.Name,
                        clientAfter.ContainerId!,
                        clientAfter.StartTimeUtc,
                        DateTimeOffset.UtcNow,
                        clientStatus))
            };
            WriteFulcioRotationJournal(
                resource.StatePath,
                operation);
            await execution.ReportAsync(
                "restart-client",
                7 + index,
                $"{client.Resource.Name} trusts both Fulcio CA generations.");
        }
        operation = operation with
        {
            Status = FulcioStatusClientsConverged,
            ClientsConvergedAtUtc = DateTimeOffset.UtcNow
        };
        WriteFulcioRotationJournal(
            resource.StatePath,
            operation);
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateFulcioCaCommand,
            "clients-converged",
            "Tesseract Restart Pending",
            "All clients trust both roots; Tesseract must restart before " +
            "Fulcio activation.");
        await runtime.PublishParentStateAsync(resource);

        await execution.ReportAsync(
            "verify-old-artifact",
            13,
            "Verifying the retained old-CA artifact in all six clients.");
        var oldValidations = await VerifyArtifactWithAllClientsAsync(
            operation.OldArtifact,
            clients,
            after.Tuf.Trust,
            operation.OldArtifactValidations,
            operation,
            isOld: true,
            cancellationToken);
        operation = operation with
        {
            OldArtifactValidations = oldValidations
        };
        WriteFulcioRotationJournal(
            resource.StatePath,
            operation);

        await execution.ReportAsync(
            "restart-tesseract",
            15,
            "Restarting the active certificate-transparency shard exactly " +
            "once with old and new roots.");
        var activeCtShard = ResolveActiveCtShardResource();
        var tesseractCurrent = runtime.GetRequiredSnapshot(activeCtShard);
        SigstoreResourceInstanceSnapshot tesseractAfter;
        if (operation.TesseractAfterContainerId is not null)
        {
            if (tesseractCurrent.ContainerId
                    != operation.TesseractAfterContainerId
                || tesseractCurrent.StartTimeUtc
                    != operation.TesseractAfterStartTimeUtc
                || !IsRunningHealthy(tesseractCurrent))
            {
                throw new InvalidDataException(
                    "The recovered Tesseract instance does not match the " +
                    "durable restart evidence.");
            }
            tesseractAfter = tesseractCurrent;
        }
        else
        {
            var originalTesseract = SnapshotFromJournal(
                operation.TesseractResourceId,
                activeCtShard.Name,
                operation.TesseractContainerId,
                operation.TesseractStartTimeUtc);
            if (IsNewInstance(
                    originalTesseract,
                    tesseractCurrent)
                && IsRunningHealthy(tesseractCurrent))
            {
                var recoveredStatus =
                    await runtime.ReadFulcioStatusAsync(
                        cancellationToken);
                if (recoveredStatus.LiveRootSha256
                        != operation.StartingFulcioRootSha256
                    || !recoveredStatus.TesseractAcceptedRootsMatch)
                {
                    throw new InvalidDataException(
                        "An unjournaled Tesseract replacement cannot be " +
                        "validated as a safe overlap restart.");
                }
                tesseractAfter = tesseractCurrent;
            }
            else if (!SameInstance(
                         originalTesseract,
                         tesseractCurrent))
            {
                throw new InvalidDataException(
                    "Tesseract changed before its ordered restart.");
            }
            else
            {
                var restart = await runtime.ExecuteCommandAsync(
                    activeCtShard,
                    KnownResourceCommands.RestartCommand,
                    cancellationToken);
                if (!restart.Success)
                {
                    throw new InvalidOperationException(
                        restart.Message
                        ?? "Aspire rejected the Tesseract restart.");
                }
                tesseractAfter = await runtime.WaitForSnapshotAsync(
                    activeCtShard,
                    snapshot => IsNewInstance(tesseractCurrent, snapshot)
                        && IsRunningHealthy(snapshot),
                    ClientTimeout,
                    cancellationToken);
                execution.Resources.Add(
                    CreateLifecycleResult(
                        tesseractAfter.Resource,
                        KnownResourceCommands.RestartCommand,
                        tesseractCurrent,
                        tesseractAfter,
                        null));
            }
            operation = operation with
            {
                Status = FulcioStatusTesseractRestarted,
                TesseractAfterContainerId = tesseractAfter.ContainerId,
                TesseractAfterStartTimeUtc = tesseractAfter.StartTimeUtc
            };
            WriteFulcioRotationJournal(
                resource.StatePath,
                operation);
        }
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateFulcioCaCommand,
            "tesseract-restarted",
            "Old Fulcio Proof Pending",
            "Tesseract has both roots; old-CA issuance and SCT proof must " +
            "complete before activation.");
        await runtime.PublishParentStateAsync(resource);

        await execution.ReportAsync(
            "prove-old-ca",
            16,
            "Proving restarted Tesseract accepts the old live Fulcio CA.");
        if (operation.OldCaProof is null)
        {
            var overlap = await runtime.ReadFulcioStatusAsync(
                cancellationToken);
            if (overlap.LiveRootSha256
                    != operation.StartingFulcioRootSha256
                || overlap.AcceptedRootSha256.Count
                    != completion.FulcioTrustEntryCount
                || !overlap.RuntimePromotionPending
                || overlap.StagedRootSha256
                    != completion.NewFulcioRootSha256
                || !overlap.AcceptedRootSha256.Contains(
                    operation.StartingFulcioRootSha256,
                    StringComparer.Ordinal)
                || !overlap.AcceptedRootSha256.Contains(
                    completion.NewFulcioRootSha256,
                    StringComparer.Ordinal))
            {
                throw new InvalidDataException(
                    "Old issuer or Tesseract additive roots are not active " +
                    "before the overlap proof.");
            }
            var (jwt, _) = await runtime.CaptureOidcTokenAsync(
                cancellationToken);
            var oldProof = await runtime.ProveFulcioIssuanceAsync(
                jwt
                    ?? throw new InvalidDataException(
                        "OIDC token response was empty."),
                SigstoreDefaults.ExpectedIdentity,
                operation.StartingFulcioRootSha256,
                cancellationToken);
            operation = operation with
            {
                Status = FulcioStatusOldCaProved,
                OldCaProof = oldProof,
                OldCaProvedAtUtc = DateTimeOffset.UtcNow
            };
            WriteFulcioRotationJournal(
                resource.StatePath,
                operation);
        }
        ValidateIssuanceProof(
            operation.OldCaProof!,
            operation.StartingFulcioRootSha256,
            operation.CtLogId,
            "old-ca-proof");
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateFulcioCaCommand,
            "old-ca-proved",
            "Fulcio Activation Pending",
            "Tesseract has proven both roots. Fulcio activation must recover " +
            "forward if interrupted.");
        await runtime.PublishParentStateAsync(resource);

        await execution.ReportAsync(
            "activate-runtime",
            17,
            "Promoting the operation-bound Fulcio runtime projection.");
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-activate-fulcio-runtime"))
        {
            _ = stateInspector.ActivateFulcioRuntimeProjection(
                resource.StatePath,
                operation.OperationId,
                operation.StartingFulcioRootSha256,
                completion.NewFulcioRootSha256);
            operation = operation with
            {
                Status = FulcioStatusRuntimeActivated,
                RuntimeActivatedAtUtc = DateTimeOffset.UtcNow
            };
            WriteFulcioRotationJournal(
                resource.StatePath,
                operation);
        }
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateFulcioCaCommand,
            "runtime-activated",
            "Fulcio Restart Pending",
            "The new runtime projection is selected; recovery must activate " +
            "Fulcio forward.");
        await runtime.PublishParentStateAsync(resource);

        await execution.ReportAsync(
            "restart-fulcio",
            18,
            "Restarting Fulcio exactly once on the new active CA.");
        var fulcioCurrent = runtime.GetRequiredSnapshot(
            resource.Components.Fulcio.Resource);
        var activationStatus = await runtime.ReadFulcioStatusAsync(
            cancellationToken);
        SigstoreResourceInstanceSnapshot fulcioAfter;
        if (operation.FulcioAfterContainerId is not null)
        {
            if (fulcioCurrent.ContainerId
                    != operation.FulcioAfterContainerId
                || fulcioCurrent.StartTimeUtc
                    != operation.FulcioAfterStartTimeUtc
                || activationStatus.LiveRootSha256
                    != completion.NewFulcioRootSha256)
            {
                throw new InvalidDataException(
                    "The recovered Fulcio activation does not match its " +
                    "durable evidence.");
            }
            fulcioAfter = fulcioCurrent;
        }
        else if (activationStatus.LiveRootSha256
                == operation.StartingFulcioRootSha256
            && fulcioCurrent.ContainerId == operation.FulcioContainerId
            && fulcioCurrent.StartTimeUtc == operation.FulcioStartTimeUtc)
        {
            var restart = await runtime.ExecuteCommandAsync(
                resource.Components.Fulcio.Resource,
                KnownResourceCommands.RestartCommand,
                cancellationToken);
            if (!restart.Success)
            {
                throw new InvalidOperationException(
                    restart.Message
                    ?? "Aspire rejected the Fulcio restart.");
            }
            fulcioAfter = await runtime.WaitForSnapshotAsync(
                resource.Components.Fulcio.Resource,
                snapshot => IsNewInstance(fulcioCurrent, snapshot)
                    && IsRunningHealthy(snapshot),
                ClientTimeout,
                cancellationToken);
            execution.Resources.Add(
                CreateLifecycleResult(
                    fulcioAfter.Resource,
                    KnownResourceCommands.RestartCommand,
                    fulcioCurrent,
                    fulcioAfter,
                    null));
        }
        else if (activationStatus.LiveRootSha256
                == completion.NewFulcioRootSha256
            && IsNewInstance(
                SnapshotFromJournal(
                    operation.FulcioResourceId,
                    resource.Components.Fulcio.Resource.Name,
                    operation.FulcioContainerId,
                    operation.FulcioStartTimeUtc),
                fulcioCurrent))
        {
            fulcioAfter = fulcioCurrent;
        }
        else
        {
            throw new InvalidDataException(
                "Fulcio cannot be activated or recovered in the required order.");
        }
        operation = operation with
        {
            Status = FulcioStatusFulcioRestarted,
            FulcioAfterContainerId = fulcioAfter.ContainerId,
            FulcioAfterStartTimeUtc = fulcioAfter.StartTimeUtc
        };
        WriteFulcioRotationJournal(
            resource.StatePath,
            operation);
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateFulcioCaCommand,
            "fulcio-restarted",
            "New Fulcio Proof Pending",
            "Fulcio is on the replacement instance; new issuance and artifact " +
            "proofs remain.");
        await runtime.PublishParentStateAsync(resource);

        await execution.ReportAsync(
            "prove-new-ca",
            19,
            "Proving real issuance and embedded SCT under the new Fulcio CA.");
        if (operation.NewCaProof is null)
        {
            var live = await runtime.ReadFulcioStatusAsync(
                cancellationToken);
            if (live.LiveRootSha256 != completion.NewFulcioRootSha256
                || !live.LiveRootMatchesActive
                || !live.RuntimeFulcioMatchesActive
                || live.RuntimePromotionPending)
            {
                throw new InvalidDataException(
                    "Fulcio does not serve the new active CA after restart.");
            }
            var (jwt, _) = await runtime.CaptureOidcTokenAsync(
                cancellationToken);
            var newProof = await runtime.ProveFulcioIssuanceAsync(
                jwt
                    ?? throw new InvalidDataException(
                        "OIDC token response was empty."),
                SigstoreDefaults.ExpectedIdentity,
                completion.NewFulcioRootSha256,
                cancellationToken);
            operation = operation with
            {
                Status = FulcioStatusNewCaProved,
                NewCaProof = newProof
            };
            WriteFulcioRotationJournal(
                resource.StatePath,
                operation);
        }
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateFulcioCaCommand,
            "new-ca-proved",
            "Artifact Verification Pending",
            "New CA issuance is proven; new artifact and six-language " +
            "verification remain.");
        await runtime.PublishParentStateAsync(resource);
        ValidateIssuanceProof(
            operation.NewCaProof!,
            completion.NewFulcioRootSha256,
            operation.CtLogId,
            "new-ca-proof");

        await execution.ReportAsync(
            "capture-new-artifact",
            20,
            "Retaining a real post-activation artifact with Rekor and TSA proof.");
        if (operation.NewArtifact is null)
        {
            operation = operation with
            {
                NewArtifact = await WaitForArtifactAsync(
                    operation.OldArtifact.ArtifactId,
                    completion.NewFulcioRootSha256,
                    cancellationToken)
            };
            WriteFulcioRotationJournal(
                resource.StatePath,
                operation);
        }

        await execution.ReportAsync(
            "verify-new-artifact",
            21,
            "Verifying the new-CA artifact in all six clients.");
        var newValidations = await VerifyArtifactWithAllClientsAsync(
            operation.NewArtifact,
            clients,
            after.Tuf.Trust,
            operation.NewArtifactValidations,
            operation,
            isOld: false,
            cancellationToken);
        operation = operation with
        {
            NewArtifactValidations = newValidations
        };
        WriteFulcioRotationJournal(
            resource.StatePath,
            operation);

        await execution.ReportAsync(
            "ct-continuity",
            23,
            "Validating CT identity, key, checkpoint, and append-only progress.");
        var finalCheckpoint = await runtime.ReadCtCheckpointAsync(
            cancellationToken);
        if (finalCheckpoint.LogId != operation.CtLogId
            || finalCheckpoint.Origin
                != operation.StartingCheckpoint.Origin
            || finalCheckpoint.TreeSize
                < operation.StartingCheckpoint.TreeSize
            || finalCheckpoint.Timestamp
                < operation.StartingCheckpoint.Timestamp
            || operation.OldCaProof!.SctTimestamp
                > finalCheckpoint.Timestamp
            || operation.NewCaProof!.SctTimestamp
                > finalCheckpoint.Timestamp)
        {
            throw new InvalidDataException(
                "Tesseract CT identity or monotonic checkpoint continuity failed.");
        }
        operation = operation with
        {
            FinalCheckpoint = finalCheckpoint
        };
        WriteFulcioRotationJournal(
            resource.StatePath,
            operation);

        await execution.ReportAsync(
            "aggregate-status",
            24,
            "Verifying disk, served TUF, clients, Tesseract, and Fulcio agree.");
        await runtime.WaitForAggregateHealthyAsync(
            AggregateTimeout,
            cancellationToken);
        var aggregate = await runtime.CollectStatusAsync(
            cancellationToken);
        execution.Check(
            "aggregate-status-ready",
            IsReadyForActiveOperation(aggregate)
                && aggregate.Clients.Count == clients.Length
                && aggregate.Fulcio is
                {
                    LiveRootMatchesActive: true,
                    RuntimeFulcioMatchesActive: true,
                    RuntimePromotionPending: false,
                    TesseractAcceptedRootsMatch: true
                },
            "ready=true with six clients and converged Fulcio/Tesseract",
            aggregate.Reason ?? $"ready={aggregate.Ready}",
            "aggregate-status",
            resource.Name);
        execution.Check(
            "protected-services-not-restarted",
            ValidateProtectedResources(
                execution,
                operation.ProtectedResources,
                "final-verification"),
            "all protected resource identities unchanged",
            "see per-resource checks",
            "final-verification",
            resource.Name);
        if (execution.HasFailures)
        {
            return execution.Failure(
                "Fulcio activation completed, but final checks failed.");
        }

        operation = operation with
        {
            Status = FulcioStatusCompleted,
            CompletedAtUtc = DateTimeOffset.UtcNow
        };
        WriteFulcioRotationJournal(
            resource.StatePath,
            operation);
        resource.ClearOperationRecovery(
            SigstoreOperationCommand.RotateFulcioCaCommand);
        execution.FulcioRotation = CreateFulcioRotationResult(
            operation,
            recovered: operation.StartedAtUtc
                < execution.Progress[0].ObservedAtUtc);
        await execution.ReportAsync(
            "complete",
            26,
            "Fulcio CA rotated with additive historical trust and CT continuity.");
        return execution.Success(
            $"Fulcio CA rotated: {operation.StartingFulcioRootSha256} -> " +
            $"{completion.NewFulcioRootSha256} (generation " +
            $"{operation.StartingGeneration} -> {completion.NewGeneration}).");
    }

    private async Task<FulcioRotationCommandJournal>
        CreateFulcioRotationOperationAsync(
            SigstoreResourceInstanceSnapshot fulcio,
            SigstoreResourceInstanceSnapshot tesseract,
            CancellationToken cancellationToken)
    {
        var starting = await CaptureAsync(cancellationToken);
        if (!MatchesServed(starting.Tuf, starting.Served))
        {
            throw new InvalidDataException(
                "Disk and served TUF state differ before Fulcio rotation.");
        }
        var fulcioStatus = await runtime.ReadFulcioStatusAsync(
            cancellationToken);
        if (!fulcioStatus.ActiveCertificateMatchesPrivateKey
            || !fulcioStatus.RuntimeFulcioMatchesActive
            || !fulcioStatus.LiveRootMatchesActive
            || !fulcioStatus.TesseractAcceptedRootsMatch
            || fulcioStatus.TrustedRoots[^1].RootSha256
                != fulcioStatus.ActiveRootSha256)
        {
            throw new InvalidDataException(
                "Fulcio, Tesseract, runtime projection, and TrustedRoot do not " +
                "agree before rotation.");
        }
        var oldArtifact = await WaitForArtifactAsync(
            0,
            fulcioStatus.ActiveRootSha256,
            cancellationToken);
        var operationId = Guid.NewGuid().ToString("N");
        var operation = new FulcioRotationCommandJournal(
            1,
            operationId,
            FulcioStatusRequested,
            DateTimeOffset.UtcNow,
            null,
            starting.Tuf.Trust.TrustDomainId,
            starting.Tuf.Trust.Generation,
            starting.Tuf.Trust.GenerationId,
            fulcioStatus.ActiveRootSha256,
            ReadGenerationDirectoryFingerprint(
                resource.StatePath,
                starting.Tuf.Trust.GenerationId),
            ReadGenerationNonFulcioFingerprint(
                resource.StatePath,
                starting.Tuf.Trust.GenerationId),
            starting,
            fulcio.ResourceId,
            fulcio.ContainerId!,
            fulcio.StartTimeUtc,
            tesseract.ResourceId,
            tesseract.ContainerId!,
            tesseract.StartTimeUtc,
            CaptureFulcioProtectedResources(),
            fulcioStatus.TrustedRoots,
            fulcioStatus.CtLogStateId,
            fulcioStatus.CtLogPublicKeySha256,
            fulcioStatus.CtLogId,
            fulcioStatus.Checkpoint,
            oldArtifact,
            null,
            null,
            [],
            null,
            [],
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            [],
            null);
        WriteFulcioRotationJournal(
            resource.StatePath,
            operation);
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateFulcioCaCommand,
            "requested",
            "Fulcio Recovery Pending",
            "The old artifact and CT identity are durable; candidate generation " +
            "or replay must complete.");
        return operation;
    }

    private async Task<SigstoreArtifactEvidence> WaitForArtifactAsync(
        long minimumExclusiveId,
        string expectedRootSha256,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow.AddMinutes(5);
        Exception? last = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                return await runtime.FindArtifactAsync(
                    minimumExclusiveId,
                    expectedRootSha256,
                    cancellationToken);
            }
            catch (InvalidDataException exception)
            {
                last = exception;
            }
            await Task.Delay(
                TimeSpan.FromSeconds(2),
                cancellationToken);
        }
        throw new InvalidDataException(
            "Timed out waiting for a sealed artifact under Fulcio root " +
            $"{expectedRootSha256}: {last?.Message}");
    }

    private async Task<IReadOnlyList<FulcioArtifactValidation>>
        VerifyArtifactWithAllClientsAsync(
            SigstoreArtifactEvidence artifact,
            IReadOnlyList<SigstoreClientRegistration> clients,
            SigstoreDiskTrustStatus trust,
            IReadOnlyList<FulcioArtifactValidation> existing,
            FulcioRotationCommandJournal operation,
            bool isOld,
            CancellationToken cancellationToken)
    {
        var results = existing.ToList();
        foreach (var client in clients)
        {
            var prior = results.SingleOrDefault(
                result => result.Resource == client.Resource.Name);
            if (prior is not null
                && prior.Evidence.ArtifactId == artifact.ArtifactId
                && prior.Evidence.ArtifactSha256
                    == artifact.ArtifactSha256
                && prior.Evidence.BundleSha256 == artifact.BundleSha256
                && prior.Evidence.Generation == trust.Generation
                && prior.Evidence.GenerationId == trust.GenerationId
                && prior.Evidence.TrustedRootSha256
                    == trust.TrustedRootSha256)
            {
                continue;
            }
            var evidence = await runtime.VerifyArtifactAsync(
                client,
                artifact,
                cancellationToken);
            if (evidence.Generation != trust.Generation
                || evidence.GenerationId != trust.GenerationId
                || evidence.TrustedRootSha256
                    != trust.TrustedRootSha256)
            {
                throw new InvalidDataException(
                    $"{client.Resource.Name} verified artifact " +
                    $"{artifact.ArtifactId} with stale trust.");
            }
            results.RemoveAll(
                result => result.Resource == client.Resource.Name);
            results.Add(
                new FulcioArtifactValidation(
                    client.Resource.Name,
                    DateTimeOffset.UtcNow,
                    evidence));
            var updated = isOld
                ? operation with
                {
                    OldArtifactValidations = results
                        .OrderBy(
                            item => item.Resource,
                            StringComparer.Ordinal)
                        .ToArray()
                }
                : operation with
                {
                    NewArtifactValidations = results
                        .OrderBy(
                            item => item.Resource,
                            StringComparer.Ordinal)
                        .ToArray()
                };
            WriteFulcioRotationJournal(
                resource.StatePath,
                updated);
        }
        return results
            .OrderBy(
                result => result.Resource,
                StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>
    /// Resolves the certificate-transparency shard that currently accepts
    /// submissions, which is the only shard a Fulcio certificate-authority
    /// rotation may extend and restart. Before a CT log shard rotation it
    /// is the historical primary shard; afterwards it is the bounded
    /// secondary shard, and the primary stays frozen, running and required
    /// so its append-only tiles and signed checkpoint remain verifiable.
    /// </summary>
    private IResource ResolveActiveCtShardResource() =>
        SigstoreCtLogShard.HasRotatedCtLog(resource.StatePath)
            ? resource.Components.TesseractSecondary.Resource
            : resource.Components.Tesseract.Resource;

    /// <summary>
    /// Rejects a Fulcio certificate-authority rotation before any mutation
    /// while a certificate-transparency log shard rotation is in flight: in
    /// that window the shard that accepts submissions, the shard Fulcio is
    /// bound to, and the accepted-root bundle that must be extended are all
    /// still moving, so the operation would be ambiguous.
    /// </summary>
    private bool ValidateCtShardRotationSettled(
        OperationExecution execution)
    {
        var incomplete = SigstoreCtLogShard.ReadRotationJournals(
                resource.StatePath)
            .Where(journal => journal.Status
                != SigstoreCtLogShard.StatusCompleted)
            .ToArray();
        var selection =
            SigstoreStateBootstrapper.ReadFulcioCtRuntimeProjection(
                resource.StatePath);
        return execution.Check(
            "ct-log-shard-rotation-settled",
            incomplete.Length == 0 && !selection.PromotionPending,
            "no in-flight certificate-transparency shard rotation",
            incomplete.Length != 0
                ? $"rotation {incomplete[0].OperationId} is " +
                    incomplete[0].Status
                : "a promoted certificate-transparency selection is pending",
            "preflight",
            resource.Name);
    }

    private IReadOnlyList<SigstoreResourceInstanceSnapshot>
        CaptureFulcioProtectedResources()
    {
        var clients = resource.GetRegistrations().Clients
            .Select(client => client.Resource.Name)
            .ToHashSet(StringComparer.Ordinal);
        return resource.GetRegistrations().RequiredResources
            .Where(
                required =>
                    required.Name
                        != resource.Components.Fulcio.Resource.Name
                    && required.Name
                        != ResolveActiveCtShardResource().Name
                    && !clients.Contains(required.Name))
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

    private void ValidateFulcioPublicationPostconditions(
        OperationExecution execution,
        FulcioRotationCommandJournal operation,
        SigstoreOperationSnapshot before,
        SigstoreOperationSnapshot after,
        FulcioRotationWorkerCompletion completion,
        SigstoreFulcioStatus status)
    {
        execution.Check(
            "generation-advanced",
            after.Tuf.Trust.Generation
                    == before.Tuf.Trust.Generation + 1
                && after.Tuf.Trust.GenerationId
                    == completion.NewGenerationId,
            $"generation {before.Tuf.Trust.Generation + 1}",
            $"generation {after.Tuf.Trust.Generation}",
            "additive-postconditions",
            "tuf-bootstrap");
        execution.Check(
            "fulcio-root-changed",
            completion.NewFulcioRootSha256
                    != operation.StartingFulcioRootSha256
                && status.ActiveRootSha256
                    == completion.NewFulcioRootSha256
                && status.LiveRootSha256
                        == operation.StartingFulcioRootSha256
                    && status.RuntimePromotionPending
                    && status.StagedRootSha256
                        == completion.NewFulcioRootSha256,
            $"disk new {completion.NewFulcioRootSha256}, live old " +
                operation.StartingFulcioRootSha256,
            $"disk {status.ActiveRootSha256}, live {status.LiveRootSha256}",
            "additive-postconditions",
            "fulcio");
        execution.Check(
            "tesseract-roots-additive-before-restart",
            status.TesseractAcceptedRootsMatch
                && status.AcceptedRootSha256.Count
                    == completion.FulcioTrustEntryCount
                && status.AcceptedRootsSha256
                    == completion.AcceptedRootsSha256,
            $"{completion.FulcioTrustEntryCount} ordered roots/" +
                completion.AcceptedRootsSha256,
            $"{status.AcceptedRootSha256.Count} roots/" +
                status.AcceptedRootsSha256,
            "additive-postconditions",
            "tesseract");
        execution.Check(
            "prior-generation-immutable",
            ReadGenerationDirectoryFingerprint(
                    resource.StatePath,
                    operation.StartingGenerationId)
                == operation.StartingGenerationDirectorySha256,
            operation.StartingGenerationDirectorySha256,
            ReadGenerationDirectoryFingerprint(
                resource.StatePath,
                operation.StartingGenerationId),
            "additive-postconditions",
            "tuf-bootstrap");
        execution.Check(
            "non-fulcio-material-unchanged",
            ReadGenerationNonFulcioFingerprint(
                    resource.StatePath,
                    after.Tuf.Trust.GenerationId)
                == operation.StartingNonFulcioMaterialSha256,
            operation.StartingNonFulcioMaterialSha256,
            ReadGenerationNonFulcioFingerprint(
                resource.StatePath,
                after.Tuf.Trust.GenerationId),
            "additive-postconditions",
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
        CheckEqual(
            execution,
            "signing-config-unchanged",
            before.Tuf.Trust.SigningConfigSha256,
            after.Tuf.Trust.SigningConfigSha256);
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
        execution.Check(
            "tuf-server-not-restarted",
            SameInstance(before.TufServer, after.TufServer)
                && IsRunningHealthy(after.TufServer),
            Describe(before.TufServer),
            Describe(after.TufServer),
            "additive-postconditions",
            after.TufServer.Resource);

        var expected = operation.StartingTrustedRoots
            .Select(root => root.RootSha256)
            .ToArray();
        var actual = status.TrustedRoots
            .Select(root => root.RootSha256)
            .ToArray();
        execution.Check(
            "old-fulcio-trust-preserved",
            actual.Take(expected.Length).SequenceEqual(
                expected,
                StringComparer.Ordinal),
            string.Join(",", expected),
            string.Join(",", actual),
            "additive-postconditions",
            "trusted_root.json");
        execution.Check(
            "new-fulcio-trust-appended",
            actual.Length == expected.Length + 1
                && actual[^1] == completion.NewFulcioRootSha256,
            $"{expected.Length + 1} roots ending in the candidate",
            $"{actual.Length} roots ending in {actual[^1]}",
            "additive-postconditions",
            "trusted_root.json");
    }

    private static void ValidateIssuanceProof(
        SigstoreFulcioIssuanceProof proof,
        string expectedRoot,
        string expectedCtLogId,
        string description)
    {
        if (!proof.SctVerified
            || proof.RootSha256 != expectedRoot
            || proof.CtLogId != expectedCtLogId
            || proof.Identity != SigstoreDefaults.ExpectedIdentity
            || proof.NotAfterUtc <= DateTimeOffset.UtcNow)
        {
            throw new InvalidDataException(
                $"{description} is not bound to the expected CA, identity, " +
                "and CT log.");
        }
    }

    private static void ValidateFulcioWorkerCompletion(
        FulcioRotationCommandJournal operation,
        FulcioRotationWorkerCompletion completion,
        SigstoreOperationSnapshot after)
    {
        if (completion.SchemaVersion != 1
            || completion.OperationId != operation.OperationId
            || completion.TrustDomainId != operation.TrustDomainId
            || completion.PriorGeneration != operation.StartingGeneration
            || completion.PriorGenerationId
                != operation.StartingGenerationId
            || completion.PriorFulcioRootSha256
                != operation.StartingFulcioRootSha256
            || completion.NewGeneration
                != operation.StartingGeneration + 1
            || completion.NewGenerationId
                != after.Tuf.Trust.GenerationId
            || completion.NewFulcioRootSha256
                != operation.CandidateFulcioRootSha256
            || completion.ManifestSha256
                != after.Tuf.Trust.GenerationManifestSha256
            || completion.PublicationId
                != after.Tuf.Trust.PublicationId
            || completion.PublicationManifestSha256
                != after.Tuf.Trust.PublicationManifestSha256
            || completion.TrustedRootSha256
                != after.Tuf.Trust.TrustedRootSha256
            || completion.SigningConfigSha256
                != after.Tuf.Trust.SigningConfigSha256
            || completion.FulcioTrustEntryCount < 2
            || !IsLowerHexSha256(completion.AcceptedRootsSha256)
            || completion.AcceptedRootFingerprints.Count
                != completion.FulcioTrustEntryCount
            || completion.AcceptedRootFingerprints.Any(
                root => !IsLowerHexSha256(root))
            || completion.ActiveFulcioRuntimeRootSha256
                != completion.PriorFulcioRootSha256
            || completion.StagedFulcioRuntimeRootSha256
                != completion.NewFulcioRootSha256)
        {
            throw new InvalidDataException(
                "The Fulcio worker completion does not match durable state.");
        }
    }

    private void ValidateFulcioJournalStartingState(
        FulcioRotationCommandJournal operation,
        OperationExecution execution)
    {
        if (operation.TrustDomainId
                != operation.StartingSnapshot.Tuf.Trust.TrustDomainId
            || operation.StartingGenerationId
                != $"generation-{operation.StartingGeneration:D8}"
            || operation.StartingSnapshot.Tuf.Trust.Generation
                != operation.StartingGeneration
            || operation.StartingSnapshot.Tuf.Trust.GenerationId
                != operation.StartingGenerationId
            || ReadGenerationDirectoryFingerprint(
                    resource.StatePath,
                    operation.StartingGenerationId)
                != operation.StartingGenerationDirectorySha256
            || ReadGenerationNonFulcioFingerprint(
                    resource.StatePath,
                    operation.StartingGenerationId)
                != operation.StartingNonFulcioMaterialSha256)
        {
            execution.AddError(
                "preflight",
                resource.Name,
                null,
                "Durable Fulcio state does not match its immutable starting " +
                "generation.");
        }
    }

    private static IReadOnlyList<FulcioClientConvergence>
        UpsertFulcioClient(
            IReadOnlyList<FulcioClientConvergence> clients,
            FulcioClientConvergence current) =>
        clients
            .Where(client => client.Resource != current.Resource)
            .Append(current)
            .OrderBy(client => client.Resource, StringComparer.Ordinal)
            .ToArray();

    private static SigstoreResourceInstanceSnapshot SnapshotFromJournal(
        string resourceId,
        string resourceName,
        string containerId,
        DateTime? startTime) =>
        new(
            resourceName,
            resourceId,
            KnownResourceStates.Running,
            nameof(HealthStatus.Healthy),
            null,
            null,
            startTime,
            null,
            containerId);

    private static ActiveFulcioGeneration ReadActiveFulcioGeneration(
        string statePath)
    {
        var link = new DirectoryInfo(
            Path.Combine(statePath, "active-generation"));
        var generationId = Path.GetFileName(
            link.LinkTarget
            ?? throw new InvalidDataException(
                "The active generation reference is missing."));
        using var document = JsonDocument.Parse(
            File.ReadAllBytes(
                Path.Combine(
                    statePath,
                    "generations",
                    generationId,
                    "manifest.json")));
        var root = document.RootElement;
        return new ActiveFulcioGeneration(
            root.GetProperty("generation").GetInt32(),
            root.GetProperty("generationId").GetString()
                ?? throw new InvalidDataException(
                    "Generation ID is missing."),
            root.GetProperty("fulcioRootSha256").GetString()
                ?? throw new InvalidDataException(
                    "Fulcio root fingerprint is missing."),
            root.TryGetProperty(
                "fulcioRotationOperationId",
                out var operation)
                ? operation.GetString()
                : null);
    }

    private static string ReadGenerationNonFulcioFingerprint(
        string statePath,
        string generationId)
    {
        var generationPath = Path.Combine(
            statePath,
            "generations",
            generationId);
        var entries = Directory.EnumerateFiles(
                generationPath,
                "*",
                SearchOption.AllDirectories)
            .Select(
                path => new
                {
                    Relative = Path.GetRelativePath(
                            generationPath,
                            path)
                        .Replace(Path.DirectorySeparatorChar, '/'),
                    Full = path
                })
            .Where(
                file => file.Relative != "manifest.json"
                    && !file.Relative.StartsWith(
                        "private/fulcio/",
                        StringComparison.Ordinal)
                    && !file.Relative.StartsWith(
                        "public/fulcio/",
                        StringComparison.Ordinal))
            .OrderBy(file => file.Relative, StringComparer.Ordinal)
            .Select(
                file => $"{file.Relative}\t" +
                    $"{Hash(File.ReadAllBytes(file.Full))}\n");
        return Hash(Encoding.UTF8.GetBytes(string.Concat(entries)));
    }

    private static FulcioRotationCommandJournal?
        LoadIncompleteFulcioRotation(string statePath)
    {
        var root = Path.Combine(statePath, "fulcio-rotation");
        if (!Directory.Exists(root))
        {
            return null;
        }
        var journals = Directory.EnumerateFiles(
                root,
                "command.json",
                SearchOption.AllDirectories)
            .Select(
                path =>
                {
                    var journal = JsonSerializer.Deserialize<
                        FulcioRotationCommandJournal>(
                            File.ReadAllBytes(path),
                            JsonOptions)
                        ?? throw new InvalidDataException(
                            $"Fulcio command journal '{path}' is empty.");
                    ValidateFulcioJournalShape(journal, path);
                    return journal;
                })
            .Where(journal => journal.Status != FulcioStatusCompleted)
            .ToArray();
        if (journals.Length > 1)
        {
            throw new InvalidDataException(
                "Multiple incomplete Fulcio rotations are ambiguous.");
        }
        return journals.SingleOrDefault();
    }

    private static void ValidateFulcioJournalShape(
        FulcioRotationCommandJournal journal,
        string path)
    {
        var statuses = new HashSet<string>(
            [
                FulcioStatusRequested,
                FulcioStatusCandidateGenerated,
                FulcioStatusWorkerCommitted,
                FulcioStatusClientsConverged,
                FulcioStatusTesseractRestarted,
                FulcioStatusOldCaProved,
                FulcioStatusRuntimeActivated,
                FulcioStatusFulcioRestarted,
                FulcioStatusNewCaProved,
                FulcioStatusCompleted
            ],
            StringComparer.Ordinal);
        if (journal.SchemaVersion != 1
            || !Guid.TryParseExact(
                journal.OperationId,
                "N",
                out _)
            || journal.OperationId.Any(char.IsUpper)
            || Path.GetFileName(Path.GetDirectoryName(path))
                != journal.OperationId
            || !statuses.Contains(journal.Status)
            || journal.StartingGeneration < 1
            || journal.StartingGenerationId
                != $"generation-{journal.StartingGeneration:D8}"
            || !IsLowerHexSha256(
                journal.StartingFulcioRootSha256)
            || !IsLowerHexSha256(
                journal.StartingGenerationDirectorySha256)
            || !IsLowerHexSha256(
                journal.StartingNonFulcioMaterialSha256)
            || !IsLowerHexSha256(journal.CtLogPublicKeySha256)
            || !IsLowerHexSha256(journal.CtLogId)
            || journal.Clients
                .Select(client => client.Resource)
                .Distinct(StringComparer.Ordinal)
                .Count() != journal.Clients.Count
            || journal.OldArtifactValidations
                .Select(item => item.Resource)
                .Distinct(StringComparer.Ordinal)
                .Count() != journal.OldArtifactValidations.Count
            || journal.NewArtifactValidations
                .Select(item => item.Resource)
                .Distinct(StringComparer.Ordinal)
                .Count() != journal.NewArtifactValidations.Count)
        {
            throw new InvalidDataException(
                $"Fulcio command journal '{path}' has invalid state.");
        }
        if (journal.Status != FulcioStatusRequested
            && journal.CandidateFulcioRootSha256 is null)
        {
            throw new InvalidDataException(
                $"Fulcio command journal '{path}' omits its candidate.");
        }
        if (journal.Status is FulcioStatusWorkerCommitted
            or FulcioStatusClientsConverged
            or FulcioStatusTesseractRestarted
            or FulcioStatusOldCaProved
            or FulcioStatusRuntimeActivated
            or FulcioStatusFulcioRestarted
            or FulcioStatusNewCaProved
            or FulcioStatusCompleted
            && journal.WorkerCompletion is null)
        {
            throw new InvalidDataException(
                $"Fulcio command journal '{path}' omits worker completion.");
        }
    }

    private static void WriteFulcioWorkerRequest(
        string statePath,
        FulcioRotationCommandJournal operation)
    {
        var request = new FulcioRotationWorkerRequest(
            1,
            operation.OperationId,
            operation.TrustDomainId,
            operation.StartingGeneration,
            operation.StartingGenerationId,
            operation.StartingFulcioRootSha256,
            operation.CandidateFulcioRootSha256
                ?? throw new InvalidDataException(
                    "Fulcio candidate fingerprint is missing."));
        var path = Path.Combine(
            statePath,
            "rotate-fulcio-ca.request");
        if (File.Exists(path))
        {
            var existing = JsonSerializer.Deserialize<
                FulcioRotationWorkerRequest>(
                    File.ReadAllBytes(path),
                    JsonOptions);
            if (existing != request)
            {
                throw new InvalidDataException(
                    "The surviving Fulcio worker request belongs to another " +
                    "operation.");
            }
            return;
        }
        WriteCreateNewJson(path, request);
    }

    private static FulcioRotationWorkerCompletion?
        ReadFulcioWorkerCompletion(string statePath)
    {
        var path = Path.Combine(
            statePath,
            "rotate-fulcio-ca.completed");
        if (!File.Exists(path))
        {
            return null;
        }
        return JsonSerializer.Deserialize<FulcioRotationWorkerCompletion>(
                File.ReadAllBytes(path),
                JsonOptions)
            ?? throw new InvalidDataException(
                "The Fulcio worker completion is empty.");
    }

    private static void WriteFulcioRotationJournal(
        string statePath,
        FulcioRotationCommandJournal operation)
    {
        var directory = FulcioOperationPath(
            statePath,
            operation.OperationId);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "command.json");
        var temporary = Path.Combine(
            directory,
            $".command.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
        var bytes = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(operation, JsonOptions) + "\n");
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
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, path, overwrite: true);
        SyncParentDirectory(path);
    }

    private static string FulcioOperationPath(
        string statePath,
        string operationId) =>
        Path.Combine(
            statePath,
            "fulcio-rotation",
            operationId);

    private static string FulcioCandidatePath(
        string statePath,
        string operationId) =>
        Path.Combine(
            FulcioOperationPath(statePath, operationId),
            "candidate");

    private static FulcioRotationEvidence CreateFulcioRotationResult(
        FulcioRotationCommandJournal operation,
        bool recovered) =>
        new(
            operation.OperationId,
            operation.Status,
            recovered,
            operation.StartingGeneration,
            operation.StartingGenerationId,
            operation.WorkerCompletion?.NewGeneration,
            operation.WorkerCompletion?.NewGenerationId,
            operation.StartingFulcioRootSha256,
            operation.WorkerCompletion?.NewFulcioRootSha256,
            operation.WorkerCompletion?.PublicationId,
            operation.WorkerCompletion?.ManifestSha256,
            operation.WorkerCompletion?.FulcioTrustEntryCount,
            operation.WorkerCompletion?.AcceptedRootsSha256,
            operation.CtLogStateId,
            operation.CtLogId,
            operation.StartingCheckpoint,
            operation.FinalCheckpoint,
            operation.OldCaProof,
            operation.NewCaProof,
            operation.OldArtifact,
            operation.NewArtifact,
            operation.FulcioContainerId,
            operation.FulcioAfterContainerId,
            operation.TesseractContainerId,
            operation.TesseractAfterContainerId,
            operation.Clients,
            operation.OldArtifactValidations,
            operation.NewArtifactValidations);
}

internal sealed record FulcioRotationWorkerRequest(
    int SchemaVersion,
    string OperationId,
    string TrustDomainId,
    int StartingGeneration,
    string StartingGenerationId,
    string StartingFulcioRootSha256,
    string CandidateFulcioRootSha256);

internal sealed record FulcioRotationWorkerCompletion(
    int SchemaVersion,
    string OperationId,
    string TrustDomainId,
    DateTimeOffset CompletedAtUtc,
    int PriorGeneration,
    string PriorGenerationId,
    string PriorFulcioRootSha256,
    int NewGeneration,
    string NewGenerationId,
    string NewFulcioRootSha256,
    string ManifestSha256,
    string PublicationId,
    string PublicationManifestSha256,
    string TrustedRootSha256,
    string SigningConfigSha256,
    int FulcioTrustEntryCount,
    string AcceptedRootsSha256,
    IReadOnlyList<string> AcceptedRootFingerprints,
    string ActiveFulcioRuntimeRootSha256,
    string StagedFulcioRuntimeRootSha256);

internal sealed record FulcioClientConvergence(
    string Resource,
    string ContainerId,
    DateTime? StartTimeUtc,
    DateTimeOffset ConvergedAtUtc,
    SigstoreClientTrustStatus TrustStatus);

internal sealed record FulcioArtifactValidation(
    string Resource,
    DateTimeOffset VerifiedAtUtc,
    SigstoreClientArtifactVerification Evidence);

internal sealed record FulcioRotationCommandJournal(
    int SchemaVersion,
    string OperationId,
    string Status,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset? CompletedAtUtc,
    string TrustDomainId,
    int StartingGeneration,
    string StartingGenerationId,
    string StartingFulcioRootSha256,
    string StartingGenerationDirectorySha256,
    string StartingNonFulcioMaterialSha256,
    SigstoreOperationSnapshot StartingSnapshot,
    string FulcioResourceId,
    string FulcioContainerId,
    DateTime? FulcioStartTimeUtc,
    string TesseractResourceId,
    string TesseractContainerId,
    DateTime? TesseractStartTimeUtc,
    IReadOnlyList<SigstoreResourceInstanceSnapshot> ProtectedResources,
    IReadOnlyList<SigstoreFulcioTrustEntry> StartingTrustedRoots,
    string CtLogStateId,
    string CtLogPublicKeySha256,
    string CtLogId,
    SigstoreCtCheckpoint StartingCheckpoint,
    SigstoreArtifactEvidence OldArtifact,
    string? CandidateFulcioRootSha256,
    FulcioRotationWorkerCompletion? WorkerCompletion,
    IReadOnlyList<FulcioClientConvergence> Clients,
    DateTimeOffset? ClientsConvergedAtUtc,
    IReadOnlyList<FulcioArtifactValidation> OldArtifactValidations,
    string? TesseractAfterContainerId,
    DateTime? TesseractAfterStartTimeUtc,
    SigstoreFulcioIssuanceProof? OldCaProof,
    DateTimeOffset? OldCaProvedAtUtc,
    DateTimeOffset? RuntimeActivatedAtUtc,
    string? FulcioAfterContainerId,
    DateTime? FulcioAfterStartTimeUtc,
    SigstoreFulcioIssuanceProof? NewCaProof,
    SigstoreArtifactEvidence? NewArtifact,
    IReadOnlyList<FulcioArtifactValidation> NewArtifactValidations,
    SigstoreCtCheckpoint? FinalCheckpoint);

internal sealed record FulcioRotationEvidence(
    string OperationId,
    string Status,
    bool Recovered,
    int StartingGeneration,
    string StartingGenerationId,
    int? NewGeneration,
    string? NewGenerationId,
    string OldRootSha256,
    string? NewRootSha256,
    string? TufPublicationId,
    string? GenerationManifestSha256,
    int? TrustedRootCount,
    string? AcceptedRootsSha256,
    string CtLogStateId,
    string CtLogId,
    SigstoreCtCheckpoint StartingCheckpoint,
    SigstoreCtCheckpoint? FinalCheckpoint,
    SigstoreFulcioIssuanceProof? OldCaProof,
    SigstoreFulcioIssuanceProof? NewCaProof,
    SigstoreArtifactEvidence OldArtifact,
    SigstoreArtifactEvidence? NewArtifact,
    string FulcioBeforeContainerId,
    string? FulcioAfterContainerId,
    string TesseractBeforeContainerId,
    string? TesseractAfterContainerId,
    IReadOnlyList<FulcioClientConvergence> Clients,
    IReadOnlyList<FulcioArtifactValidation> OldArtifactValidations,
    IReadOnlyList<FulcioArtifactValidation> NewArtifactValidations);

internal sealed record ActiveFulcioGeneration(
    int Generation,
    string GenerationId,
    string FulcioRootSha256,
    string? FulcioRotationOperationId);
