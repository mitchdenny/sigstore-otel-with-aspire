using System.Security.Cryptography;
using System.Text.Json;
using Sigstore.Oidc;
using Xunit;

namespace Sigstore.Bootstrap.Tests;

public sealed class OidcTokenIssuerTests : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        $"sigstore-oidc-issuer-{Guid.NewGuid():N}");

    public OidcTokenIssuerTests() => Directory.CreateDirectory(root);

    public void Dispose() => Directory.Delete(root, recursive: true);

    [Fact]
    public void LoadAcceptsOverlapAndSignsWithMatchingActiveKey()
    {
        using var active = RSA.Create(2048);
        using var historical = RSA.Create(2048);
        var (privatePath, jwksPath, activeKid) = WriteMaterial(
            active,
            [CreateJwk(active), CreateJwk(historical)]);

        using var issuer = OidcTokenIssuer.Load(
            "https://issuer.example.test",
            privatePath,
            jwksPath,
            "demo@example.test");
        var header = ReadJwtHeader(issuer.CreateToken("demo@example.test"));

        Assert.Equal("RS256", header.GetProperty("alg").GetString());
        Assert.Equal(activeKid, header.GetProperty("kid").GetString());
    }

    [Fact]
    public void LoadRejectsDuplicateKeyIds()
    {
        using var active = RSA.Create(2048);
        var key = CreateJwk(active);
        var (privatePath, jwksPath, _) = WriteMaterial(
            active,
            [key, key]);

        var error = Assert.Throws<InvalidDataException>(() =>
            OidcTokenIssuer.Load(
                "https://issuer.example.test",
                privatePath,
                jwksPath,
                "demo@example.test"));
        Assert.Contains("duplicate", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LoadRejectsInvalidHistoricalKey()
    {
        using var active = RSA.Create(2048);
        using var historical = RSA.Create(2048);
        var invalid = CreateJwk(historical) with { Alg = "RS512" };
        var (privatePath, jwksPath, _) = WriteMaterial(
            active,
            [CreateJwk(active), invalid]);

        var error = Assert.Throws<InvalidDataException>(() =>
            OidcTokenIssuer.Load(
                "https://issuer.example.test",
                privatePath,
                jwksPath,
                "demo@example.test"));
        Assert.Contains("algorithm", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    private (string PrivatePath, string JwksPath, string Kid) WriteMaterial(
        RSA active,
        IReadOnlyList<TestJwk> keys)
    {
        var privatePath = Path.Combine(root, "signer.key");
        var jwksPath = Path.Combine(root, "jwks.json");
        File.WriteAllText(privatePath, active.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(
            jwksPath,
            JsonSerializer.Serialize(new { keys }, JsonOptions));
        return (privatePath, jwksPath, CreateJwk(active).Kid);
    }

    private static TestJwk CreateJwk(RSA key)
    {
        var parameters = key.ExportParameters(false);
        return new TestJwk(
            "RSA",
            "sig",
            Base64Url(SHA256.HashData(key.ExportSubjectPublicKeyInfo())),
            "RS256",
            Base64Url(parameters.Modulus!),
            Base64Url(parameters.Exponent!));
    }

    private static JsonElement ReadJwtHeader(string jwt)
    {
        var encoded = jwt.Split('.')[0].Replace('-', '+').Replace('_', '/');
        encoded += (encoded.Length % 4) switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => throw new InvalidDataException()
        };
        using var document = JsonDocument.Parse(Convert.FromBase64String(encoded));
        return document.RootElement.Clone();
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private sealed record TestJwk(
        string Kty,
        string Use,
        string Kid,
        string Alg,
        string N,
        string E);
}
