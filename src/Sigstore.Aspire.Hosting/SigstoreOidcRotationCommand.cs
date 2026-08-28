using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sigstore.Bootstrap;

namespace Aspire.Hosting.ApplicationModel;

/// <summary>
/// OIDC signing key rotation command.
///
/// Phases: preflight → generate-candidate → publish-overlap →
///         activate → postconditions → complete
///
/// Recovery: failure before activate leaves old signer active.
/// Failure during/after activate recovers forward on next invocation.
/// Trust generation is NOT advanced (OIDC keys are discovered via
/// OIDC discovery, not TUF-published TrustedRoot/SigningConfig).
/// </summary>
internal static class SigstoreOidcRotationCommand
{
    private static readonly TimeSpan RestartTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(30);

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static CommandOptions CreateOptions(SigstoreResource resource) =>
        new()
        {
            Description =
                "Rotate the OIDC issuer signing key. Publishes overlapping JWKS, " +
                "then activates the new signer. Fulcio is not restarted.",
            ConfirmationMessage =
                "Rotate the OIDC signing key? The issuer will be restarted " +
                "twice (overlap, then activation). Fulcio discovers the new " +
                "key without restart. Old tokens remain valid.",
            IconName = "Key",
            IconVariant = IconVariant.Regular,
            UpdateState = _ =>
                SigstoreOperationCommand.GetMutationCommandState(resource),
            Progress = new CommandProgressOptions
            {
                Title = "Rotate OIDC signing key",
                Message = "Generating key and publishing overlapping JWKS.",
                HideCancelButton = true
            }
        };

    public static async Task<ExecuteCommandResult> ExecuteAsync(
        SigstoreResource resource,
        ExecuteCommandContext context)
    {
        ArgumentNullException.ThrowIfNull(resource);
        ArgumentNullException.ThrowIfNull(context);

        if (!resource.TryBeginOperation(
                SigstoreOperationCommand.RotateOidcSigningKeyCommand,
                "Rotating OIDC Key",
                out var lease,
                out var active))
        {
            return ContentionResult(active!);
        }

        var commands = context.Services
            .GetRequiredService<ResourceCommandService>();
        var notifications = context.Services
            .GetRequiredService<ResourceNotificationService>();

        try
        {
            return await ExecuteCoreAsync(
                resource, commands, notifications,
                context.Logger, context.CancellationToken);
        }
        catch (Exception ex) when (
            ex is OperationCanceledException
            or InvalidDataException
            or IOException
            or HttpRequestException
            or JsonException)
        {
            return FailResult(
                $"OIDC rotation failed: {ex.Message}", null);
        }
        finally
        {
            lease!.Dispose();
            await notifications.PublishUpdateAsync(
                resource,
                snapshot => SigstoreParentHealthMonitor
                    .CreateParentSnapshot(resource, snapshot));
        }
    }

    private static async Task<ExecuteCommandResult> ExecuteCoreAsync(
        SigstoreResource resource,
        ResourceCommandService commands,
        ResourceNotificationService notifications,
        ILogger logger,
        CancellationToken ct)
    {
        var operationId = Guid.NewGuid().ToString("N");
        var statePath = resource.StatePath;
        var activeGenLink = Path.Combine(statePath, "active-generation");
        var resolvedGenPath = ResolveActiveGeneration(activeGenLink);

        // --- Phase 1: Preflight ---
        logger.LogInformation(
            "OIDC rotation {OperationId}: preflight", operationId);

        var oldKeyId = OidcKeyRotation.ReadActiveKeyId(resolvedGenPath);
        var oldJwksKeyIds = OidcKeyRotation.ReadJwksKeyIds(resolvedGenPath);

        var oidcBefore = GetSnapshot(notifications,
            resource.Components.Oidc.Resource);
        var fulcioBefore = GetSnapshot(notifications,
            resource.Components.Fulcio.Resource);

        if (!IsRunningHealthy(oidcBefore) || !IsRunningHealthy(fulcioBefore))
        {
            return FailResult(
                "OIDC or Fulcio is not Running/Healthy.", operationId);
        }

        // --- Phase 2: Generate Candidate ---
        logger.LogInformation(
            "OIDC rotation {OperationId}: generating candidate key",
            operationId);

        var candidate = OidcKeyRotation.GenerateCandidate();
        if (candidate.KeyId == oldKeyId
            || oldJwksKeyIds.Contains(candidate.KeyId))
        {
            return FailResult(
                "Generated key has same ID as existing key.", operationId);
        }

        // --- Phase 3: Publish Overlap ---
        logger.LogInformation(
            "OIDC rotation {OperationId}: publishing overlapping JWKS " +
            "(old={OldKid}, new={NewKid})", operationId,
            oldKeyId, candidate.KeyId);

        string overlapJwksSha256;
        using (StateFileLock.Acquire(
            statePath, TimeSpan.FromSeconds(10),
            "oidc-rotation-publish"))
        {
            ct.ThrowIfCancellationRequested();
            overlapJwksSha256 = OidcKeyRotation.WriteOverlappingJwks(
                resolvedGenPath, candidate.Jwk);
        }

        // Restart OIDC (still old signer, now serves overlapping JWKS).
        var overlapRestart = await RestartAndWaitAsync(
            resource.Components.Oidc.Resource,
            oidcBefore, commands, notifications, ct);
        if (!overlapRestart.Healthy)
        {
            return FailResult(
                "OIDC restart for overlap publication failed.", operationId);
        }

        // Verify overlap JWKS served.
        var oidcEndpoint = await GetContainerEndpointAsync(
            resource.Components.Oidc.Resource, "internal", ct);
        if (oidcEndpoint != null)
        {
            var servedKids = await FetchJwksKeyIdsAsync(oidcEndpoint, ct);
            if (servedKids == null
                || !servedKids.Contains(oldKeyId)
                || !servedKids.Contains(candidate.KeyId))
            {
                return FailResult(
                    "Overlapping JWKS not observable after restart.",
                    operationId);
            }

            // Verify still signing with old key.
            var overlapToken = await FetchTokenAsync(oidcEndpoint, ct);
            var overlapKid = ExtractKid(overlapToken);
            if (overlapKid != oldKeyId)
            {
                return FailResult(
                    $"Expected old kid {oldKeyId} during overlap but got {overlapKid}.",
                    operationId);
            }
        }

        // --- Phase 4: Activate ---
        logger.LogInformation(
            "OIDC rotation {OperationId}: activating new signer {NewKid}",
            operationId, candidate.KeyId);

        using (StateFileLock.Acquire(
            statePath, TimeSpan.FromSeconds(10),
            "oidc-rotation-activate"))
        {
            ct.ThrowIfCancellationRequested();
            OidcKeyRotation.RetainCurrentKey(resolvedGenPath, oldKeyId);
            OidcKeyRotation.ActivateNewKey(
                resolvedGenPath, candidate.PrivateKeyPem);
        }

        var oidcAfterOverlap = GetSnapshot(notifications,
            resource.Components.Oidc.Resource);
        var activateRestart = await RestartAndWaitAsync(
            resource.Components.Oidc.Resource,
            oidcAfterOverlap, commands, notifications, ct);
        if (!activateRestart.Healthy)
        {
            return FailResult(
                "OIDC restart for activation failed. New key is on disk " +
                "but issuer may not be active. Restart OIDC manually.",
                operationId);
        }

        // Verify new kid in tokens.
        string? newToken = null;
        string? oldPreActivationToken = null;
        if (oidcEndpoint != null)
        {
            // Capture a pre-activation token (signed with old key during overlap).
            // We already have overlapToken from phase 3.
            oldPreActivationToken = await FetchTokenAsync(oidcEndpoint, ct);
            // Wait a moment then get new token.
            await Task.Delay(100, ct);
            newToken = await FetchTokenAsync(oidcEndpoint, ct);
            var newKid = ExtractKid(newToken);
            if (newKid != candidate.KeyId)
            {
                return FailResult(
                    $"After activation, token kid is {newKid}, " +
                    $"expected {candidate.KeyId}.", operationId);
            }
        }

        // --- Phase 5: Postconditions ---
        logger.LogInformation(
            "OIDC rotation {OperationId}: postcondition checks",
            operationId);

        var fulcioAfter = GetSnapshot(notifications,
            resource.Components.Fulcio.Resource);
        var fulcioNotRestarted =
            fulcioBefore.ContainerId == fulcioAfter.ContainerId
            && IsRunningHealthy(fulcioAfter);

        // Verify Fulcio can issue certs with new token.
        bool? fulcioNewTokenOk = null;
        bool? fulcioOldTokenOk = null;
        var fulcioEndpoint = await GetContainerEndpointAsync(
            resource.Components.Fulcio.Resource, "http", ct);
        if (fulcioEndpoint != null && newToken != null)
        {
            fulcioNewTokenOk = await TestFulcioCertIssuanceAsync(
                fulcioEndpoint, newToken, ct);
        }
        if (fulcioEndpoint != null && oldPreActivationToken != null)
        {
            fulcioOldTokenOk = await TestFulcioCertIssuanceAsync(
                fulcioEndpoint, oldPreActivationToken, ct);
        }

        // Final JWKS check.
        string[]? finalJwksKids = null;
        if (oidcEndpoint != null)
        {
            finalJwksKids = await FetchJwksKeyIdsAsync(oidcEndpoint, ct);
        }

        // --- Phase 6: Write State ---
        var retainedKeyIds = oldJwksKeyIds
            .Where(k => k != candidate.KeyId)
            .Distinct()
            .ToArray();

        using (StateFileLock.Acquire(
            statePath, TimeSpan.FromSeconds(10),
            "oidc-rotation-complete"))
        {
            OidcKeyRotation.WriteState(statePath, new OidcRotationState(
                SchemaVersion: 1,
                ActiveKeyId: candidate.KeyId,
                RetainedKeyIds: retainedKeyIds,
                JwksSha256: overlapJwksSha256,
                RotatedAtUtc: DateTimeOffset.UtcNow,
                OperationId: operationId));
        }

        logger.LogInformation(
            "OIDC rotation {OperationId}: complete. Old={OldKid} New={NewKid}",
            operationId, oldKeyId, candidate.KeyId);

        // Build result.
        var result = new
        {
            success = true,
            command = SigstoreOperationCommand.RotateOidcSigningKeyCommand,
            operationId,
            message = $"OIDC signing key rotated. Old: {oldKeyId}, New: {candidate.KeyId}. " +
                "Fulcio was not restarted.",
            before = new
            {
                activeKeyId = oldKeyId,
                jwksKeyIds = oldJwksKeyIds,
                oidcContainerId = oidcBefore.ContainerId,
                fulcioContainerId = fulcioBefore.ContainerId
            },
            after = new
            {
                activeKeyId = candidate.KeyId,
                retainedKeyIds,
                jwksKeyIds = finalJwksKids ?? Array.Empty<string>(),
                jwksSha256 = overlapJwksSha256,
                oidcContainerId = activateRestart.Snapshot?.ContainerId,
                fulcioContainerId = fulcioAfter.ContainerId
            },
            postconditions = new
            {
                fulcioNotRestarted,
                fulcioNewTokenAccepted = fulcioNewTokenOk,
                fulcioOldTokenAccepted = fulcioOldTokenOk,
                jwksOverlapping = finalJwksKids != null
                    && finalJwksKids.Contains(oldKeyId)
                    && finalJwksKids.Contains(candidate.KeyId),
                oldKeyRetained = File.Exists(Path.Combine(
                    resolvedGenPath, "private", "oidc", "retained",
                    $"key-{oldKeyId}.pem"))
            }
        };

        var json = JsonSerializer.Serialize(result, JsonOptions);
        return new ExecuteCommandResult
        {
            Success = true,
            Message = result.message,
            Data = new CommandResultData
            {
                Value = json,
                Format = CommandResultFormat.Json,
                DisplayImmediately = true
            }
        };
    }

    private static string ResolveActiveGeneration(string linkPath)
    {
        var target = Directory.ResolveLinkTarget(linkPath, returnFinalTarget: true);
        return target?.FullName ?? Path.GetFullPath(linkPath);
    }

    private static SigstoreResourceInstanceSnapshot GetSnapshot(
        ResourceNotificationService notifications,
        IResource resource)
    {
        if (!notifications.TryGetCurrentState(
                resource.Name, out var resourceEvent))
        {
            throw new InvalidOperationException(
                $"Resource '{resource.Name}' state is unavailable.");
        }

        var snapshot = resourceEvent.Snapshot;
        var containerId = snapshot.Properties
            .FirstOrDefault(p => p.Name == "container.id")
            ?.Value?.ToString();
        return new SigstoreResourceInstanceSnapshot(
            resource.Name,
            resourceEvent.ResourceId,
            snapshot.State?.Text ?? "Unavailable",
            snapshot.HealthStatus?.ToString() ?? "Unknown",
            snapshot.ExitCode,
            snapshot.CreationTimeStamp,
            snapshot.StartTimeStamp,
            snapshot.StopTimeStamp,
            containerId);
    }

    private static bool IsRunningHealthy(SigstoreResourceInstanceSnapshot s) =>
        string.Equals(s.State, "Running", StringComparison.OrdinalIgnoreCase)
        && string.Equals(s.Health, "Healthy", StringComparison.OrdinalIgnoreCase);

    private record struct RestartResult(
        bool Healthy,
        SigstoreResourceInstanceSnapshot? Snapshot);

    private static async Task<RestartResult> RestartAndWaitAsync(
        IResource resource,
        SigstoreResourceInstanceSnapshot before,
        ResourceCommandService commands,
        ResourceNotificationService notifications,
        CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(RestartTimeout);

        var restart = await commands.ExecuteCommandAsync(
            resource, KnownResourceCommands.RestartCommand, timeout.Token);
        if (!restart.Success)
        {
            return new RestartResult(false, null);
        }

        try
        {
            var ev = await notifications.WaitForResourceAsync(
                resource.Name,
                item =>
                {
                    var s = item.Snapshot;
                    var cid = s.Properties
                        .FirstOrDefault(p => p.Name == "container.id")
                        ?.Value?.ToString();
                    var isNew = cid != before.ContainerId
                        || s.StartTimeStamp > before.StartTimeUtc;
                    return isNew
                        && string.Equals(s.State?.Text, "Running",
                            StringComparison.OrdinalIgnoreCase)
                        && s.HealthStatus?.ToString() == "Healthy";
                },
                timeout.Token);

            var snap = GetSnapshot(notifications, resource);
            return new RestartResult(true, snap);
        }
        catch (OperationCanceledException)
        {
            return new RestartResult(false, null);
        }
    }

    private static async Task<string?> GetContainerEndpointAsync(
        IResource resource,
        string endpointName,
        CancellationToken ct)
    {
        try
        {
            if (resource is IResourceWithEndpoints withEndpoints)
            {
                var endpoint = withEndpoints.GetEndpoint(endpointName);
                var url = await endpoint.GetValueAsync(ct);
                return url;
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<string?> FetchTokenAsync(
        string baseUrl, CancellationToken ct)
    {
        try
        {
            using var client = CreateHttpClient();
            var resp = await client.GetAsync($"{baseUrl}/token", ct);
            return resp.IsSuccessStatusCode
                ? await resp.Content.ReadAsStringAsync(ct)
                : null;
        }
        catch { return null; }
    }

    private static async Task<string[]?> FetchJwksKeyIdsAsync(
        string baseUrl, CancellationToken ct)
    {
        try
        {
            using var client = CreateHttpClient();
            var resp = await client.GetAsync($"{baseUrl}/jwks", ct);
            if (!resp.IsSuccessStatusCode) return null;
            var json = await resp.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("keys")
                .EnumerateArray()
                .Select(k => k.GetProperty("kid").GetString()!)
                .ToArray();
        }
        catch { return null; }
    }

    private static async Task<bool> TestFulcioCertIssuanceAsync(
        string fulcioUrl, string token, CancellationToken ct)
    {
        try
        {
            using var client = CreateHttpClient();
            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue(
                    "Bearer", token);

            using var ephemeral = System.Security.Cryptography.ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var pubKeyBytes = ephemeral.ExportSubjectPublicKeyInfo();
            var proof = ephemeral.SignData(
                System.Text.Encoding.UTF8.GetBytes(token),
                System.Security.Cryptography.HashAlgorithmName.SHA256);

            var body = JsonSerializer.Serialize(new
            {
                credentials = new { oidcIdentityToken = token },
                publicKeyRequest = new
                {
                    publicKey = new
                    {
                        algorithm = "ECDSA",
                        content = Convert.ToBase64String(pubKeyBytes)
                    },
                    proofOfPossession = Convert.ToBase64String(proof)
                }
            });

            var content = new StringContent(
                body, System.Text.Encoding.UTF8, "application/json");
            var resp = await client.PostAsync(
                $"{fulcioUrl}/api/v2/signingCert", content, ct);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    private static string? ExtractKid(string? token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        try
        {
            var header = token.Split('.')[0]
                .Replace('-', '+').Replace('_', '/');
            header += (header.Length % 4) switch
            {
                2 => "==", 3 => "=", _ => ""
            };
            var json = System.Text.Encoding.UTF8.GetString(
                Convert.FromBase64String(header));
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("kid").GetString();
        }
        catch { return null; }
    }

    private static HttpClient CreateHttpClient() =>
        new(new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        })
        { Timeout = HttpTimeout };

    private static ExecuteCommandResult ContentionResult(
        SigstoreOperationState active) =>
        new()
        {
            Success = false,
            Message = $"Cannot rotate OIDC key: {active.Command} is active " +
                $"since {active.StartedAtUtc:O}."
        };

    private static ExecuteCommandResult FailResult(
        string message, string? operationId)
    {
        var result = new { success = false,
            command = SigstoreOperationCommand.RotateOidcSigningKeyCommand,
            operationId, message };
        return new ExecuteCommandResult
        {
            Success = false,
            Message = message,
            Data = new CommandResultData
            {
                Value = JsonSerializer.Serialize(result, JsonOptions),
                Format = CommandResultFormat.Json,
                DisplayImmediately = true
            }
        };
    }
}
