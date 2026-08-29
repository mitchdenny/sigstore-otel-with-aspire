using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

public sealed record SigstoreComponents(
    IResourceBuilder<SigstoreResource> Parent,
    IResourceBuilder<ProjectResource> Bootstrap,
    IResourceBuilder<ContainerResource> StateReady,
    IResourceBuilder<ContainerResource> Oidc,
    IResourceBuilder<ContainerResource> Tesseract,
    IResourceBuilder<ContainerResource> TesseractSecondary,
    IResourceBuilder<ContainerResource> Fulcio,
    IResourceBuilder<ContainerResource> Timestamp,
    IResourceBuilder<ContainerResource> RekorServer,
    IResourceBuilder<ContainerResource> RekorServerSecondary,
    IResourceBuilder<ContainerResource> Rekor,
    IResourceBuilder<ContainerResource> TufBootstrap,
    IResourceBuilder<ContainerResource> TufStateReady,
    IResourceBuilder<ContainerResource> Tuf);
