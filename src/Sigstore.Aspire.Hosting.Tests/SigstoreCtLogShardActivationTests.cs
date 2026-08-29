using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Xunit;

namespace Sigstore.Aspire.Hosting.Tests;

/// <summary>
/// Topology and lifecycle coverage for the certificate-transparency shard
/// rotation. The secondary shard must be a genuinely separate logical log
/// — its own explicit-start compute, isolated signer mount, isolated
/// storage and canonical stable URL — and the historical primary shard's
/// compute must stay required forever, because previously issued
/// certificates are only auditable while it keeps serving its append-only
/// tiles and signed checkpoint.
/// </summary>
public sealed class SigstoreCtLogShardActivationTests
{
    [Fact]
    public void SecondaryShardIsConditionalAndPrimaryStaysRequired()
    {
        using var model = new CtActivationModelFixture();
        var resource = model.Parent.Resource;

        var registrations = resource.GetRegistrations();

        Assert.Contains(
            registrations.RequiredResources,
            item => ReferenceEquals(
                item,
                resource.Components.Tesseract.Resource));
        Assert.Contains(
            registrations.ConditionalResources,
            item => ReferenceEquals(
                item,
                resource.Components.TesseractSecondary.Resource));
        Assert.False(
            resource.IsConditionalResourceActive(
                resource.Components.TesseractSecondary.Resource.Name));
        Assert.DoesNotContain(
            resource.Components.TesseractSecondary.Resource.Name,
            EffectiveRequiredNames(resource));
    }

    [Fact]
    public void ActivatingTheSecondaryNeverRetiresThePrimaryShard()
    {
        using var model = new CtActivationModelFixture();
        var resource = model.Parent.Resource;

        resource.ActivateConditionalResource(
            resource.Components.TesseractSecondary.Resource);

        var effective = EffectiveRequiredNames(resource);
        Assert.Contains(
            resource.Components.Tesseract.Resource.Name,
            effective);
        Assert.Contains(
            resource.Components.TesseractSecondary.Resource.Name,
            effective);
        Assert.Contains(
            resource.GetRegistrations().RequiredResources,
            item => ReferenceEquals(
                item,
                resource.Components.Tesseract.Resource));

        // Replay after a resumed operation is idempotent.
        resource.ActivateConditionalResource(
            resource.Components.TesseractSecondary.Resource);
        Assert.Equal(effective, EffectiveRequiredNames(resource));
    }

    [Fact]
    public void AStoppedHistoricalPrimaryShardDegradesTheParent()
    {
        using var model = new CtActivationModelFixture();
        var resource = model.Parent.Resource;
        resource.ActivateConditionalResource(
            resource.Components.TesseractSecondary.Resource);

        var observed = new Dictionary<string, SigstoreObservedResource>(
            StringComparer.Ordinal)
        {
            [resource.Components.Tesseract.Resource.Name] =
                new(KnownResourceStates.Exited, HealthStatus.Unhealthy),
            [resource.Components.TesseractSecondary.Resource.Name] =
                new(KnownResourceStates.Running, HealthStatus.Healthy)
        };
        foreach (var required in resource.GetRegistrations()
            .RequiredResources)
        {
            observed.TryAdd(
                required.Name,
                new SigstoreObservedResource(
                    KnownResourceStates.Running,
                    HealthStatus.Healthy));
        }

        var health = SigstoreParentHealthMonitor.Evaluate(
            EffectiveRequiredNames(resource),
            observed,
            wasHealthy: true);

        Assert.Equal("Degraded", health.State);
        Assert.Contains(
            health.Resources,
            status => status.Resource
                == resource.Components.Tesseract.Resource.Name);
    }

    [Fact]
    public void TheTwoShardsHaveIsolatedMountsStorageAndEndpoints()
    {
        using var model = new CtActivationModelFixture();
        var resource = model.Parent.Resource;
        var primary = resource.Components.Tesseract.Resource;
        var secondary = resource.Components.TesseractSecondary.Resource;

        var primaryMounts = MountSources(primary);
        var secondaryMounts = MountSources(secondary);
        Assert.Empty(primaryMounts.Intersect(secondaryMounts));
        Assert.Contains(
            primaryMounts,
            path => path.EndsWith(
                Path.Combine("runtime", "tesseract"),
                StringComparison.Ordinal));
        Assert.Contains(
            secondaryMounts,
            path => path.EndsWith(
                Path.Combine("runtime", "tesseract-secondary"),
                StringComparison.Ordinal));
        Assert.Contains(
            secondaryMounts,
            path => path.EndsWith(
                Path.Combine("data", "ctlog-shards", "secondary"),
                StringComparison.Ordinal));

        // The secondary shard's signer mount is read-only and carries only
        // its own material.
        Assert.All(
            secondary.Annotations
                .OfType<ContainerMountAnnotation>()
                .Where(mount => mount.Target
                    == "/var/lib/sigstore/tesseract"),
            mount => Assert.True(mount.IsReadOnly));

        Assert.Contains(
            "--origin=tesseract-secondary-sigstore.dev.localhost",
            Args(secondary));
        Assert.Contains(
            "--origin=tesseract-sigstore.dev.localhost",
            Args(primary));

        var secondaryEndpoint = secondary.Annotations
            .OfType<EndpointAnnotation>()
            .Single(endpoint => endpoint.Name == "http");
        var primaryEndpoint = primary.Annotations
            .OfType<EndpointAnnotation>()
            .Single(endpoint => endpoint.Name == "http");
        Assert.Equal(6962, primaryEndpoint.Port);
        Assert.Equal(6963, secondaryEndpoint.Port);
    }

    [Fact]
    public void TheSecondaryShardOnlyStartsWhenTheRotationStartsIt()
    {
        using var model = new CtActivationModelFixture();
        var secondary = model.Parent.Resource.Components
            .TesseractSecondary.Resource;

        Assert.Contains(
            secondary.Annotations.OfType<ExplicitStartupAnnotation>(),
            _ => true);
        Assert.DoesNotContain(
            model.Parent.Resource.Components.Tesseract.Resource.Annotations
                .OfType<ExplicitStartupAnnotation>(),
            _ => true);
    }

    [Fact]
    public async Task FulcioResolvesItsCtLogBindingFromTheRuntimeSelection()
    {
        using var model = new CtActivationModelFixture();
        var fulcio = model.Parent.Resource.Components.Fulcio.Resource;

        // The CT log Fulcio binds to must not be a build-time argument;
        // it is promoted durably and read at startup.
        Assert.DoesNotContain(
            Args(fulcio),
            argument => argument.StartsWith(
                "--ct-log-",
                StringComparison.Ordinal));
        Assert.Contains(
            fulcio.Annotations.OfType<ContainerMountAnnotation>(),
            mount => mount.Target == "/var/lib/sigstore/fulcio-ct"
                && mount.IsReadOnly);

        // Both shard addresses are supplied so the promotion is a pure
        // selector flip that needs no model change.
        var environment = new EnvironmentCallbackContext(
            new DistributedApplicationExecutionContext(
                DistributedApplicationOperation.Run),
            fulcio);
        foreach (var annotation in fulcio.Annotations
            .OfType<EnvironmentCallbackAnnotation>())
        {
            await annotation.Callback(environment);
        }
        Assert.Contains(
            "SIGSTORE_CT_LOG_URL_PRIMARY",
            environment.EnvironmentVariables.Keys);
        Assert.Equal(
            "http://tesseract-secondary:6962",
            environment.EnvironmentVariables[
                "SIGSTORE_CT_LOG_URL_SECONDARY"]);
    }

    private static IReadOnlyList<string> Args(IResource resource) =>
        resource.Annotations
            .OfType<CommandLineArgsCallbackAnnotation>()
            .SelectMany(
                annotation =>
                {
                    var context = new CommandLineArgsCallbackContext([]);
                    annotation.Callback(context).GetAwaiter().GetResult();
                    return context.Args.OfType<string>();
                })
            .ToArray();

    private static IReadOnlyList<string> MountSources(IResource resource) =>
        resource.Annotations
            .OfType<ContainerMountAnnotation>()
            .Where(mount => mount.Source is not null)
            .Select(mount => mount.Source!)
            .ToArray();

    private static HashSet<string> EffectiveRequiredNames(
        SigstoreResource resource)
    {
        var registrations = resource.GetRegistrations();
        return registrations.RequiredResources
            .Select(item => item.Name)
            .Concat(
                registrations.ConditionalResources
                    .Where(
                        item => resource.IsConditionalResourceActive(
                            item.Name))
                    .Select(item => item.Name))
            .ToHashSet(StringComparer.Ordinal);
    }

    private sealed class CtActivationModelFixture : IDisposable
    {
        public CtActivationModelFixture()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-ct-activation-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
            Directory.CreateDirectory(
                System.IO.Path.Combine(Path, ".sigstore"));
            var sourcePath = System.IO.Path.Combine(
                FindRepositoryRoot(),
                "src");
            Builder = DistributedApplication.CreateBuilder(
                new DistributedApplicationOptions
                {
                    AssemblyName =
                        typeof(SigstoreCtLogShardActivationTests)
                            .Assembly.FullName,
                    ProjectDirectory = Path,
                    DisableDashboard = true
                });
            Parent = Builder.AddSigstore(
                "sigstore",
                new SigstoreOptions
                {
                    SourcePath = sourcePath
                });
        }

        public string Path { get; }

        public IDistributedApplicationBuilder Builder { get; }

        public IResourceBuilder<SigstoreResource> Parent { get; }

        public void Dispose()
        {
            Directory.Delete(Path, recursive: true);
        }

        private static string FindRepositoryRoot()
        {
            for (var directory = new DirectoryInfo(
                    AppContext.BaseDirectory);
                directory is not null;
                directory = directory.Parent)
            {
                if (File.Exists(
                        System.IO.Path.Combine(
                            directory.FullName,
                            "apphost.cs"))
                    && Directory.Exists(
                        System.IO.Path.Combine(
                            directory.FullName,
                            "src",
                            "Sigstore.Bootstrap")))
                {
                    return directory.FullName;
                }
            }

            throw new DirectoryNotFoundException(
                "Unable to locate the repository root for hosting tests.");
        }
    }
}
