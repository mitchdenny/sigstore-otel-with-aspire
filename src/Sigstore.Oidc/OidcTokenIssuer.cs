using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sigstore.Oidc;

internal sealed class OidcTokenIssuer : IDisposable
{
    private const string Audience = "sigstore";
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    private readonly Lock signingLock = new();
    private readonly RSA signingKey;
    private readonly string keyId;

    private OidcTokenIssuer(
        string issuer,
        string defaultIdentity,
        string jwksJson,
        string keyId,
        RSA signingKey)
    {
        Issuer = issuer;
        DefaultIdentity = defaultIdentity;
        JwksJson = jwksJson;
        this.keyId = keyId;
        this.signingKey = signingKey;
    }

    public string Issuer { get; }

    public string DefaultIdentity { get; }

    public string JwksJson { get; }

    public static OidcTokenIssuer Load(
        string issuer,
        string privateKeyPath,
        string jwksPath,
        string defaultIdentity)
    {
        var normalizedIssuer = NormalizeIssuer(issuer);
        if (!IsValidIdentity(defaultIdentity))
        {
            throw new InvalidDataException(
                "The default OIDC identity must be an email address.");
        }

        var signingKey = RSA.Create();
        try
        {
            signingKey.ImportFromPem(
                File.ReadAllText(privateKeyPath));
            var jwksJson = File.ReadAllText(jwksPath);
            var keyId = ValidateJwks(signingKey, jwksJson);

            return new OidcTokenIssuer(
                normalizedIssuer,
                defaultIdentity,
                jwksJson,
                keyId,
                signingKey);
        }
        catch
        {
            signingKey.Dispose();
            throw;
        }
    }

    public object CreateDiscoveryDocument() => new
    {
        issuer = Issuer,
        jwks_uri = $"{Issuer}/jwks",
        token_endpoint = $"{Issuer}/token",
        response_types_supported = new[]
        {
            "id_token"
        },
        subject_types_supported = new[]
        {
            "public"
        },
        id_token_signing_alg_values_supported = new[]
        {
            "RS256"
        },
        scopes_supported = new[]
        {
            "openid",
            "email"
        },
        claims_supported = new[]
        {
            "iss",
            "sub",
            "aud",
            "iat",
            "nbf",
            "exp",
            "email",
            "email_verified"
        }
    };

    public string CreateToken(string identity)
    {
        if (!IsValidIdentity(identity))
        {
            throw new ArgumentException(
                "The identity must be an email address.",
                nameof(identity));
        }

        var now = DateTimeOffset.UtcNow;
        var header = JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                alg = "RS256",
                kid = keyId,
                typ = "JWT"
            },
            JsonOptions);
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                iss = Issuer,
                sub = identity,
                aud = Audience,
                iat = now.ToUnixTimeSeconds(),
                nbf = now.AddSeconds(-5).ToUnixTimeSeconds(),
                exp = now.AddMinutes(30).ToUnixTimeSeconds(),
                email = identity,
                email_verified = true
            },
            JsonOptions);
        var signingInput =
            $"{Base64UrlEncode(header)}.{Base64UrlEncode(payload)}";
        byte[] signature;

        lock (signingLock)
        {
            signature = signingKey.SignData(
                Encoding.ASCII.GetBytes(signingInput),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
        }

        return $"{signingInput}.{Base64UrlEncode(signature)}";
    }

    public static bool IsValidIdentity(string identity)
    {
        if (string.IsNullOrWhiteSpace(identity)
            || identity.Length > 254
            || identity.Any(char.IsWhiteSpace))
        {
            return false;
        }

        var atIndex = identity.IndexOf('@');
        return atIndex > 0
            && atIndex == identity.LastIndexOf('@')
            && atIndex < identity.Length - 1;
    }

    public void Dispose() => signingKey.Dispose();

    private static string NormalizeIssuer(string issuer)
    {
        if (!Uri.TryCreate(
            issuer,
            UriKind.Absolute,
            out var uri)
            || !string.Equals(
                uri.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidDataException(
                "The OIDC issuer must be an absolute HTTPS URL.");
        }

        return uri.AbsoluteUri.TrimEnd('/');
    }

    private static string ValidateJwks(
        RSA signingKey,
        string jwksJson)
    {
        using var document = JsonDocument.Parse(jwksJson);
        if (document.RootElement.ValueKind != JsonValueKind.Object
            || !document.RootElement.TryGetProperty("keys", out var keysElement)
            || keysElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException(
                "The OIDC JWKS must contain a keys array.");
        }
        var keys = keysElement.EnumerateArray().ToArray();

        if (keys.Length < 1)
        {
            throw new InvalidDataException(
                "The OIDC JWKS must contain at least one key.");
        }

        var expectedKeyId = Base64UrlEncode(
            SHA256.HashData(
                signingKey.ExportSubjectPublicKeyInfo()));
        var seenKids = new HashSet<string>(StringComparer.Ordinal);
        var activeMatches = 0;
        foreach (var candidate in keys)
        {
            if (candidate.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException(
                    "Every OIDC JWK must be an object.");
            }
            var kid = RequiredString(candidate, "kid");
            if (kid.Length != 43
                || kid.Any(character =>
                    !char.IsAsciiLetterOrDigit(character)
                    && character is not ('-' or '_'))
                || !seenKids.Add(kid))
            {
                throw new InvalidDataException(
                    "The OIDC JWKS contains an invalid or duplicate key ID.");
            }
            EnsureEqual("key type", "RSA", RequiredString(candidate, "kty"));
            EnsureEqual("key use", "sig", RequiredString(candidate, "use"));
            EnsureEqual("algorithm", "RS256", RequiredString(candidate, "alg"));

            var parameters = new RSAParameters
            {
                Modulus = Base64UrlDecode(RequiredString(candidate, "n")),
                Exponent = Base64UrlDecode(RequiredString(candidate, "e"))
            };
            using var candidateKey = RSA.Create();
            try
            {
                candidateKey.ImportParameters(parameters);
            }
            catch (CryptographicException exception)
            {
                throw new InvalidDataException(
                    $"The OIDC JWK '{kid}' is not a valid RSA public key.",
                    exception);
            }
            if (candidateKey.KeySize < 2048)
            {
                throw new InvalidDataException(
                    $"The OIDC JWK '{kid}' must use at least 2048 RSA bits.");
            }
            EnsureEqual(
                "key ID",
                kid,
                Base64UrlEncode(
                    SHA256.HashData(
                        candidateKey.ExportSubjectPublicKeyInfo())));
            if (kid == expectedKeyId)
            {
                EnsureKeyBytesEqual(
                    "active public key",
                    signingKey.ExportSubjectPublicKeyInfo(),
                    candidateKey.ExportSubjectPublicKeyInfo());
                activeMatches++;
            }
        }
        if (activeMatches != 1)
        {
            throw new InvalidDataException(
                "The OIDC JWKS must contain exactly one key matching " +
                "the private signer.");
        }

        return expectedKeyId;
    }

    private static string RequiredString(
        JsonElement element,
        string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property)
            || property.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(property.GetString()))
        {
            throw new InvalidDataException(
                $"The OIDC JWK property '{propertyName}' is required.");
        }
        return property.GetString()!;
    }

    private static void EnsureKeyBytesEqual(
        string description,
        byte[] expected,
        byte[] actual)
    {
        if (!CryptographicOperations.FixedTimeEquals(
            expected,
            actual))
        {
            throw new InvalidDataException(
                $"The OIDC JWKS {description} does not match " +
                "the private key.");
        }
    }

    private static void EnsureEqual(
        string description,
        string expected,
        string? actual)
    {
        if (!string.Equals(
            expected,
            actual,
            StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The OIDC JWKS {description} is invalid.");
        }
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static byte[] Base64UrlDecode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException(
                "The OIDC JWKS contains an empty key value.");
        }

        var padded = value
            .Replace('-', '+')
            .Replace('_', '/');
        padded += (padded.Length % 4) switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => throw new InvalidDataException(
                "The OIDC JWKS contains invalid base64url data.")
        };

        return Convert.FromBase64String(padded);
    }
}
