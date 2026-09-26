using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Pat.Onboarding.Core;
using Xunit;

// Every trust decision is tested BOTH ways: the genuine case is accepted, and each forgery refused.
public class Fixture
{
    public static readonly DateTimeOffset Now = new DateTimeOffset(2026, 9, 25, 0, 0, 0, TimeSpan.Zero);
    public static readonly Uri Portal = new Uri("https://iip.example.test");
    public const string Serial = "6139-9449-0657-5249-0646-3842-82";

    public ECDsa PatKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public TrustedKey Trusted;
    public byte[] CaDer;
    public string CaPem;

    public Fixture()
    {
        var p = PatKey.ExportParameters(false);
        Trusted = new TrustedKey("pat-tenant-test-1", p.Q.X, p.Q.Y);
        using (var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var req = new CertificateRequest("CN=test machine CA", caKey, HashAlgorithmName.SHA256);
            var ca = req.CreateSelfSigned(Now.AddDays(-1), Now.AddYears(5));
            CaDer = ca.Export(X509ContentType.Cert);
        }
        CaPem = "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(CaDer, Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE-----\n";
    }

    public static string Hex(byte[] b) { using (var h = SHA256.Create()) return BitConverter.ToString(h.ComputeHash(b)).Replace("-", "").ToLowerInvariant(); }

    public string Envelope(object doc = null, ECDsa signer = null, string kid = "pat-tenant-test-1", Func<byte[], byte[]> tamper = null)
    {
        var d = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(doc ?? new
        {
            v = 1, tenant = "example-demo", portal = "https://iip.example.test", concentrator = "odj.example.test",
            machine_ca_sha256 = Hex(CaDer), not_after = "2027-09-25T00:00:00Z"
        }));
        var sig = (signer ?? PatKey).SignData(d, HashAlgorithmName.SHA256);   // .NET: IEEE P1363 r||s
        if (tamper != null) d = tamper(d);
        return JsonSerializer.Serialize(new { kid, doc = Convert.ToBase64String(d), sig = Convert.ToBase64String(sig) });
    }

    public TenantDocument Tenant() => TenantDocument.Verify(Envelope(), Trusted, Portal, Now);

    public static byte[] BlobGz(string base64Text, bool bom = true)
    {
        var file = new List<byte>();
        if (bom) file.AddRange(new byte[] { 0xFF, 0xFE });
        file.AddRange(Encoding.Unicode.GetBytes(base64Text + "\0"));
        using (var ms = new MemoryStream())
        {
            using (var gz = new GZipStream(ms, CompressionLevel.Optimal, true)) gz.Write(file.ToArray(), 0, file.Count);
            return ms.ToArray();
        }
    }

    public byte[] Bundle(string caPem = null, bool extra = false)
    {
        using (var ms = new MemoryStream())
        {
            using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true))
            {
                void Add(string n, string c) { using (var s = z.CreateEntry(n).Open()) { var b = Encoding.ASCII.GetBytes(c); s.Write(b, 0, b.Length); } }
                Add("machine.crt", "CERT"); Add("machine.key", "KEY"); Add("machine-ca-bundle.pem", caPem ?? CaPem); Add("machine-tc.key", "TC");
                if (extra) Add("evil.dll", "x");
            }
            return ms.ToArray();
        }
    }

    // A real byte array encoded ONCE: the ODJ NDR header, then filler. (The first version appended
    // 'A's after base64 that had already ended in '=' padding - invalid base64, which the code
    // rightly refused.)
    public static readonly string BlobText = Convert.ToBase64String(Header8());
    static byte[] Header8() { var b = new byte[2384]; new byte[] { 1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc }.CopyTo(b, 0); return b; }

    public string TokenResponse(string serial = Serial, string server = "odj.example.test", byte[] blobGz = null, byte[] bundle = null, string name = "DMO1LVM001", bool corruptHash = false)
    {
        blobGz = blobGz ?? BlobGz(BlobText);
        bundle = bundle ?? Bundle();
        return JsonSerializer.Serialize(new
        {
            serial, name, server, port = 1195, tun_mtu = 1400,
            blob_sha256 = corruptHash ? new string('0', 64) : Hex(blobGz).ToUpperInvariant(), bundle_sha256 = Hex(bundle).ToUpperInvariant(),
            blob_gz_b64 = Convert.ToBase64String(blobGz), bundle_b64 = Convert.ToBase64String(bundle)
        });
    }
}

public class TenantDocumentTests
{
    readonly Fixture f = new Fixture();

    [Fact] public void GenuineDocumentIsAccepted()
    {
        var t = f.Tenant();
        Assert.Equal("odj.example.test", t.Concentrator);
        Assert.Equal(Fixture.Hex(f.CaDer), t.MachineCaSha256);
    }

    // The Linux pins (pat-platform ADR 0058) are EXTRA fields in the same v1 document. Every Windows
    // installer already deployed must keep accepting a document that carries them - re-signing a
    // tenant for Linux laptops must not break its Windows ones.
    [Fact] public void DocumentWithLinuxPinsIsStillAcceptedOnWindows()
    {
        var t = TenantDocument.Verify(f.Envelope(new
        {
            v = 1, tenant = "example-demo", portal = "https://iip.example.test", concentrator = "odj.example.test",
            machine_ca_sha256 = Fixture.Hex(f.CaDer), not_after = "2027-09-25T00:00:00Z",
            ad_domain = "demo.example.test", ad_ca_sha256 = new string('a', 64)
        }), f.Trusted, Fixture.Portal, Fixture.Now);
        Assert.Equal("odj.example.test", t.Concentrator);
    }

    [Fact] public void TamperedDocumentIsRefused() =>
        Assert.Throws<TrustException>(() => TenantDocument.Verify(f.Envelope(tamper: d => { d[10] ^= 1; return d; }), f.Trusted, Fixture.Portal, Fixture.Now));

    [Fact] public void DocumentSignedByAnotherKeyIsRefused()
    {
        using (var other = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            Assert.Throws<TrustException>(() => TenantDocument.Verify(f.Envelope(signer: other), f.Trusted, Fixture.Portal, Fixture.Now));
    }

    [Fact] public void UnknownKeyIdIsRefused() =>
        Assert.Throws<TrustException>(() => TenantDocument.Verify(f.Envelope(kid: "someone-else"), f.Trusted, Fixture.Portal, Fixture.Now));

    // The attack this whole mechanism exists for: a genuinely signed document, served by an
    // attacker's host that the installer was pointed at.
    [Fact] public void GenuineDocumentServedByAnotherHostIsRefused()
    {
        var e = Assert.Throws<TrustException>(() => TenantDocument.Verify(f.Envelope(), f.Trusted, new Uri("https://evil.example"), Fixture.Now));
        Assert.Contains("not https://evil.example", e.Message);
    }

    [Fact] public void ExpiredDocumentIsRefused() =>
        Assert.Throws<TrustException>(() => TenantDocument.Verify(f.Envelope(), f.Trusted, Fixture.Portal, new DateTimeOffset(2028, 1, 1, 0, 0, 0, TimeSpan.Zero)));

    [Fact] public void HttpPortalInDocumentIsRefused() =>
        Assert.Throws<TrustException>(() => TenantDocument.Verify(f.Envelope(new
        {
            v = 1, tenant = "x", portal = "http://iip.example.test", concentrator = "odj.example.test",
            machine_ca_sha256 = new string('a', 64), not_after = "2027-09-25T00:00:00Z"
        }), f.Trusted, new Uri("http://iip.example.test"), Fixture.Now));

    [Fact] public void GarbageIsRefusedNotCrashed() =>
        Assert.Throws<TrustException>(() => TenantDocument.Verify("<html>not json</html>", f.Trusted, Fixture.Portal, Fixture.Now));
}

public class PayloadTests
{
    readonly Fixture f = new Fixture();

    [Fact] public void GenuinePayloadIsAcceptedAndBlobDecodesToBinary()
    {
        var p = Payload.Accept(f.TokenResponse(), Fixture.Serial.ToLowerInvariant() + " ", f.Tenant());
        Assert.Equal("DMO1LVM001", p.Name);
        Assert.Equal(new byte[] { 1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc }, p.ProvisionBinData[..8]);   // the NDR header
        Assert.Equal(4, p.Bundle.Count);
    }

    [Fact] public void PayloadForAnotherMachineIsRefused() =>
        Assert.Throws<TrustException>(() => Payload.Accept(f.TokenResponse(), "SOME-OTHER-SERIAL", f.Tenant()));

    [Fact] public void TunnelPointedAtAnotherServerIsRefused() =>
        Assert.Throws<TrustException>(() => Payload.Accept(f.TokenResponse(server: "evil.example"), Fixture.Serial, f.Tenant()));

    [Fact] public void SubstitutedMachineCaIsRefused()
    {
        var other = new Fixture();   // a different, valid CA
        Assert.Throws<TrustException>(() => Payload.Accept(f.TokenResponse(bundle: f.Bundle(caPem: other.CaPem)), Fixture.Serial, f.Tenant()));
    }

    [Fact] public void HashMismatchIsRefused() =>
        Assert.Throws<TrustException>(() => Payload.Accept(f.TokenResponse(corruptHash: true), Fixture.Serial, f.Tenant()));

    [Fact] public void UnexpectedBundleMemberIsRefused() =>
        Assert.Throws<TrustException>(() => Payload.Accept(f.TokenResponse(bundle: f.Bundle(extra: true)), Fixture.Serial, f.Tenant()));

    // RCA-53's defect, from the other side: the blob must be in the measured djoin format.
    [Fact] public void BlobWithoutBomIsRefused() =>
        Assert.Throws<TrustException>(() => Payload.Accept(f.TokenResponse(blobGz: Fixture.BlobGz(Fixture.BlobText, bom: false)), Fixture.Serial, f.Tenant()));

    [Fact] public void InvalidComputerNameIsRefused() =>
        Assert.Throws<TrustException>(() => Payload.Accept(f.TokenResponse(name: "../../evil"), Fixture.Serial, f.Tenant()));
}

public class TunnelProfileTests
{
    [Fact] public void ProfileCarriesTheProvenDirectives()
    {
        var p = TunnelProfile.Render("odj.example.test", 1195, 1400);
        foreach (var l in new[] { "remote odj.example.test 1195", "tls-crypt machine-tc.key", "remote-cert-eku \"TLS Web Server Authentication\"",
                                  "verify-x509-name odj.example.test name", "tun-mtu 1400", "ca machine-ca.pem" })
            Assert.Contains(l + "\r\n", p);
    }

    [Fact] public void InjectionThroughTheServerNameIsRefused() =>
        Assert.Throws<ArgumentException>(() => TunnelProfile.Render("odj.example.test\r\nscript-security 3", 1195, 1400));
}

public class PairingClientTests
{
    sealed class Fake : HttpMessageHandler
    {
        public readonly Queue<(HttpStatusCode, string)> Replies = new Queue<(HttpStatusCode, string)>();
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            var (code, body) = Replies.Dequeue();
            return Task.FromResult(new HttpResponseMessage(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    static string StartReply(string host = "iip.example.test") => JsonSerializer.Serialize(new
    {
        device_code = "dc", user_code = "BCDF-GHJK", verification_uri = $"https://{host}/odj/approve",
        verification_uri_complete = $"https://{host}/odj/approve?code=BCDF-GHJK", expires_in = 600, interval = 0
    });

    [Fact] public async Task PendingThenApproved()
    {
        var fake = new Fake();
        fake.Replies.Enqueue((HttpStatusCode.OK, StartReply()));
        fake.Replies.Enqueue((HttpStatusCode.BadRequest, "{\"error\":\"authorization_pending\"}"));
        fake.Replies.Enqueue((HttpStatusCode.OK, "{\"serial\":\"X\"}"));
        var c = new PairingClient(Fixture.Portal, fake);
        var s = await c.StartAsync("X", CancellationToken.None);
        s.Interval = 0;
        int waits = 0;
        Assert.Equal("{\"serial\":\"X\"}", await c.PollAsync(s, () => waits++, CancellationToken.None));
        Assert.Equal(1, waits);
        Assert.Null(s.DeviceCode);   // the bearer secret is dropped once used
    }

    [Fact] public async Task ApprovalLinkOnAnotherHostIsRefused()
    {
        var fake = new Fake();
        fake.Replies.Enqueue((HttpStatusCode.OK, StartReply("evil.example")));
        await Assert.ThrowsAsync<TrustException>(() => new PairingClient(Fixture.Portal, fake).StartAsync("X", CancellationToken.None));
    }

    [Fact] public async Task DeniedAndExpiredStop()
    {
        foreach (var err in new[] { "access_denied", "expired_token" })
        {
            var fake = new Fake();
            fake.Replies.Enqueue((HttpStatusCode.OK, StartReply()));
            fake.Replies.Enqueue((HttpStatusCode.BadRequest, $"{{\"error\":\"{err}\"}}"));
            var c = new PairingClient(Fixture.Portal, fake);
            var s = await c.StartAsync("X", CancellationToken.None); s.Interval = 0;
            await Assert.ThrowsAsync<PairingException>(() => c.PollAsync(s, null, CancellationToken.None));
        }
    }

    [Fact] public async Task PortalWithoutATenantDocumentIsRefused()
    {
        var fake = new Fake();
        fake.Replies.Enqueue((HttpStatusCode.NotFound, "not found"));
        await Assert.ThrowsAsync<TrustException>(() => new PairingClient(Fixture.Portal, fake).GetTenantEnvelopeAsync(CancellationToken.None));
    }

    [Fact] public void PlainHttpPortalIsRefused() =>
        Assert.Throws<ArgumentException>(() => new PairingClient(new Uri("http://iip.example.test")));
}

// Interop: an envelope produced by tools/sign-tenant-document.py (openssl DER -> P1363) must verify
// under the C# verifier. Data/python-signed-envelope.json was signed with the DEV tenant key for
// https://iip.example.test; the X/Y below are that key's public point (as in TrustedKeys.cs).
public class SigningToolInteropTests
{
    static TrustedKey DevKey() => new TrustedKey("pat-tenant-dev-2026-09",
        Convert.FromHexString("ce8ad6549cba838f23c5f7a261ea9c2f4923083638b04832489e1f0231c54f16"),
        Convert.FromHexString("ead05ca68bf652cf1e712a01d52a4517865298f2e7f5a26dce02f55b821a5ef5"));

    static string Envelope() => System.IO.File.ReadAllText(System.IO.Path.Combine(AppContext.BaseDirectory, "Data", "python-signed-envelope.json"));

    [Fact] public void PythonSignedEnvelopeVerifies()
    {
        var t = TenantDocument.Verify(Envelope(), DevKey(), new Uri("https://iip.example.test"), Fixture.Now);
        Assert.Equal("example", t.Tenant);
        Assert.Equal("odj.example.test", t.Concentrator);
    }

    [Fact] public void PythonSignedEnvelopeWithOneBitFlippedIsRefused()
    {
        using var d = JsonDocument.Parse(Envelope());
        var sig = Convert.FromBase64String(d.RootElement.GetProperty("sig").GetString());
        sig[0] ^= 1;
        var forged = JsonSerializer.Serialize(new { kid = "pat-tenant-dev-2026-09", doc = d.RootElement.GetProperty("doc").GetString(), sig = Convert.ToBase64String(sig) });
        Assert.Throws<TrustException>(() => TenantDocument.Verify(forged, DevKey(), new Uri("https://iip.example.test"), Fixture.Now));
    }
}
