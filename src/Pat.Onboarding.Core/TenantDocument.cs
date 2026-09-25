using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Pat.Onboarding.Core
{
    /// <summary>
    /// The trust anchor (ADR 0057 phases 2-3, section 1). A portal is only believed if it serves a
    /// tenant document SIGNED BY PAT, and only for the portal named inside it. Without this, anyone
    /// who can point the installer at their own portal can have the laptop joined to THEIR domain.
    ///
    /// Wire format, served at https://&lt;portal&gt;/.well-known/pat-onboarding.json:
    ///   { "kid": "...", "doc": "&lt;base64 of the exact document bytes&gt;", "sig": "&lt;base64 ECDSA P-256 / SHA-256, IEEE P1363 r||s&gt;" }
    /// The signature covers the decoded bytes of "doc" exactly - no JSON canonicalisation to get wrong.
    /// </summary>
    public sealed class TenantDocument
    {
        public string Tenant { get; private set; }
        public Uri Portal { get; private set; }
        public string Concentrator { get; private set; }
        public string MachineCaSha256 { get; private set; }
        public DateTimeOffset NotAfter { get; private set; }

        /// <summary>
        /// Verify and parse. Throws TrustException on ANY doubt: unknown key id, bad signature,
        /// wrong portal, expired, malformed. There is no "warn and continue" path.
        /// </summary>
        public static TenantDocument Verify(string envelopeJson, TrustedKey key, Uri portalAsked, DateTimeOffset now)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (portalAsked == null) throw new ArgumentNullException(nameof(portalAsked));
            string kid, docB64, sigB64;
            try
            {
                using (var env = JsonDocument.Parse(envelopeJson))
                {
                    kid = env.RootElement.GetProperty("kid").GetString();
                    docB64 = env.RootElement.GetProperty("doc").GetString();
                    sigB64 = env.RootElement.GetProperty("sig").GetString();
                }
            }
            catch (Exception e) when (e is JsonException || e is InvalidOperationException || e is System.Collections.Generic.KeyNotFoundException)
            {
                throw new TrustException("the portal's tenant document is not a valid envelope", e);
            }
            if (!string.Equals(kid, key.KeyId, StringComparison.Ordinal))
                throw new TrustException($"the tenant document is signed with key '{kid}', not the one this installer trusts ('{key.KeyId}')");

            byte[] doc, sig;
            try { doc = Convert.FromBase64String(docB64); sig = Convert.FromBase64String(sigB64); }
            catch (FormatException e) { throw new TrustException("the tenant document is not base64", e); }

            if (!key.Verify(doc, sig))
                throw new TrustException("the tenant document's signature is NOT valid - this portal is not one PAT has enrolled");

            var t = new TenantDocument();
            try
            {
                using (var d = JsonDocument.Parse(doc))
                {
                    var r = d.RootElement;
                    if (r.GetProperty("v").GetInt32() != 1) throw new TrustException("unsupported tenant document version");
                    t.Tenant = r.GetProperty("tenant").GetString();
                    t.Portal = new Uri(r.GetProperty("portal").GetString(), UriKind.Absolute);
                    t.Concentrator = r.GetProperty("concentrator").GetString();
                    t.MachineCaSha256 = r.GetProperty("machine_ca_sha256").GetString().ToLowerInvariant();
                    t.NotAfter = DateTimeOffset.Parse(r.GetProperty("not_after").GetString(), System.Globalization.CultureInfo.InvariantCulture);
                }
            }
            catch (TrustException) { throw; }
            catch (Exception e) { throw new TrustException("the signed tenant document is malformed", e); }

            // The portal we are TALKING to must be the one the document names. Otherwise a copied,
            // genuinely signed document for another portal would vouch for an attacker's host.
            if (t.Portal.Scheme != Uri.UriSchemeHttps || !SameOrigin(t.Portal, portalAsked))
                throw new TrustException($"the tenant document is for {t.Portal.GetLeftPart(UriPartial.Authority)}, not {portalAsked.GetLeftPart(UriPartial.Authority)}");
            if (now >= t.NotAfter)
                throw new TrustException($"the tenant document expired {t.NotAfter:u}");
            if (!Checks.IsHostName(t.Concentrator) || !Checks.IsHex(t.MachineCaSha256, 64) || string.IsNullOrWhiteSpace(t.Tenant))
                throw new TrustException("the signed tenant document carries an invalid field");
            return t;
        }

        private static bool SameOrigin(Uri a, Uri b) =>
            a.Scheme == b.Scheme && a.Port == b.Port && string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A PAT tenant-signing public key (ECDSA P-256), compiled into the installer.</summary>
    public sealed class TrustedKey
    {
        public string KeyId { get; }
        private readonly ECParameters _p;

        public TrustedKey(string keyId, byte[] x, byte[] y)
        {
            if (string.IsNullOrEmpty(keyId) || x == null || y == null || x.Length != 32 || y.Length != 32)
                throw new ArgumentException("a P-256 key needs a key id and 32-byte X and Y");
            KeyId = keyId;
            _p = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } };
        }

        public bool Verify(byte[] data, byte[] p1363Signature)
        {
            using (var ec = ECDsa.Create())
            {
                ec.ImportParameters(_p);
                return p1363Signature != null && p1363Signature.Length == 64 && ec.VerifyData(data, p1363Signature, HashAlgorithmName.SHA256);
            }
        }
    }

    public sealed class TrustException : Exception
    {
        public TrustException(string m) : base(m) { }
        public TrustException(string m, Exception inner) : base(m, inner) { }
    }

    internal static class Checks
    {
        public static bool IsHex(string s, int len)
        {
            if (s == null || s.Length != len) return false;
            foreach (var c in s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            return true;
        }

        public static bool IsHostName(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length > 253) return false;
            foreach (var c in s) if (!(char.IsLetterOrDigit(c) && c < 128) && c != '-' && c != '.') return false;
            return s.Contains(".") && !s.StartsWith(".") && !s.EndsWith(".");
        }

        /// <summary>[SITE]L&lt;1-10 of A-Z 0-9 -&gt; (naming.yaml workstations), within NetBIOS's 15.</summary>
        public static bool IsNetbiosLaptopName(string s)
        {
            if (s == null || s.Length < 6 || s.Length > 15 || s[4] != 'L') return false;
            for (int i = 0; i < s.Length; i++)
            {
                var c = s[i];
                bool ok = (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (i > 4 && c == '-');
                if (!ok) return false;
            }
            return true;
        }

        public static string Sha256Hex(byte[] data)
        {
            using (var h = SHA256.Create())
            {
                var b = h.ComputeHash(data);
                var sb = new StringBuilder(64);
                foreach (var x in b) sb.Append(x.ToString("x2"));
                return sb.ToString();
            }
        }
    }
}
