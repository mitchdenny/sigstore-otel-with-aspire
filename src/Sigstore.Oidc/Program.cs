using Sigstore.Oidc;

var builder = WebApplication.CreateBuilder(args);
var issuer = OidcTokenIssuer.Load(
    GetRequiredEnvironmentVariable("SIGSTORE_OIDC_ISSUER"),
    GetRequiredEnvironmentVariable("SIGSTORE_OIDC_PRIVATE_KEY_PATH"),
    GetRequiredEnvironmentVariable("SIGSTORE_OIDC_JWKS_PATH"),
    Environment.GetEnvironmentVariable(
        "SIGSTORE_OIDC_DEFAULT_IDENTITY")
        ?? "demo@sigstore.local");

builder.Services.AddSingleton(issuer);

var app = builder.Build();

app.MapGet(
    "/",
    (OidcTokenIssuer tokenIssuer) => Results.Json(new
    {
        warning = "This unauthenticated issuer is for local testing only.",
        issuer = tokenIssuer.Issuer,
        defaultIdentity = tokenIssuer.DefaultIdentity
    }));

app.MapGet(
    "/.well-known/openid-configuration",
    (OidcTokenIssuer tokenIssuer) =>
        Results.Json(tokenIssuer.CreateDiscoveryDocument()));

app.MapGet(
    "/jwks",
    (OidcTokenIssuer tokenIssuer) =>
        Results.Text(
            tokenIssuer.JwksJson,
            contentType: "application/json"));

app.MapGet(
    "/token",
    (
        HttpContext context,
        OidcTokenIssuer tokenIssuer,
        string? identity) =>
    {
        var selectedIdentity =
            identity ?? tokenIssuer.DefaultIdentity;
        if (!OidcTokenIssuer.IsValidIdentity(selectedIdentity))
        {
            return Results.BadRequest(new
            {
                error = "identity must be an email address"
            });
        }

        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";

        return Results.Text(
            tokenIssuer.CreateToken(selectedIdentity),
            contentType: "text/plain");
    });

app.MapGet(
    "/healthz",
    () => Results.Json(new
    {
        status = "SERVING"
    }));

app.Logger.LogWarning(
    "The test OIDC issuer performs no authentication. Issuer: {Issuer}",
    issuer.Issuer);

app.Run();

static string GetRequiredEnvironmentVariable(string name) =>
    Environment.GetEnvironmentVariable(name)
    ?? throw new InvalidOperationException(
        $"{name} must be configured.");
