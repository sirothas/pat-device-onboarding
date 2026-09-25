using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace Pat.Onboarding.Core
{
    /// <summary>
    /// The one-time payload the portal releases after the employee approves (POST /odj/pair/token).
    /// Accepted only if it is bound to THIS machine, THIS tenant and its own hashes - every check here
    /// runs before anything touches the operating system.
    /// </summary>
    public sealed class Payload
    {
        public string Serial { get; private set; }
        public string Name { get; private set; }
        public string Server { get; private set; }
        public int Port { get; private set; }
        public int TunMtu { get; private set; }
        /// <summary>The ODJ provisioning data, BINARY - what NetRequestOfflineDomainJoin takes. No file.</summary>
        public byte[] ProvisionBinData { get; private set; }
        /// <summary>machine.crt, machine.key, machine-ca-bundle.pem, machine-tc.key.</summary>
        public IReadOnlyDictionary<string, byte[]> Bundle { get; private set; }

        public static readonly string[] BundleMembers = { "machine.crt", "machine.key", "machine-ca-bundle.pem", "machine-tc.key" };

        public static Payload Accept(string tokenResponseJson, string thisMachineSerial, TenantDocument tenant)
        {
            if (tenant == null) throw new ArgumentNullException(nameof(tenant));
            var p = new Payload();
            string blobB64, bundleB64, blobSha, bundleSha;
            try
            {
                using (var d = JsonDocument.Parse(tokenResponseJson))
                {
                    var r = d.RootElement;
                    p.Serial = r.GetProperty("serial").GetString();
                    p.Name = r.GetProperty("name").GetString();
                    p.Server = r.GetProperty("server").GetString();
                    p.Port = r.GetProperty("port").GetInt32();
                    p.TunMtu = r.GetProperty("tun_mtu").GetInt32();
                    blobB64 = r.GetProperty("blob_gz_b64").GetString();
                    bundleB64 = r.GetProperty("bundle_b64").GetString();
                    blobSha = r.GetProperty("blob_sha256").GetString().ToLowerInvariant();
                    bundleSha = r.GetProperty("bundle_sha256").GetString().ToLowerInvariant();
                }
            }
            catch (Exception e) when (!(e is TrustException)) { throw new TrustException("the portal's payload is malformed", e); }

            if (Serials.Normalise(p.Serial) != Serials.Normalise(thisMachineSerial))
                throw new TrustException($"the payload is for serial {p.Serial}, this machine is {thisMachineSerial}");
            if (!string.Equals(p.Server, tenant.Concentrator, StringComparison.OrdinalIgnoreCase))
                throw new TrustException($"the payload points the tunnel at {p.Server}, the signed tenant document says {tenant.Concentrator}");
            if (p.Port < 1 || p.Port > 65535 || p.TunMtu < 576 || p.TunMtu > 1500)
                throw new TrustException("the payload's port or MTU is out of range");
            if (!Checks.IsNetbiosLaptopName(p.Name))
                throw new TrustException($"the payload's computer name '{p.Name}' is not a valid laptop name");

            byte[] blobGz = Convert.FromBase64String(blobB64), bundle = Convert.FromBase64String(bundleB64);
            if (Checks.Sha256Hex(blobGz) != blobSha) throw new TrustException("the join blob does not match its hash");
            if (Checks.Sha256Hex(bundle) != bundleSha) throw new TrustException("the certificate bundle does not match its hash");

            p.ProvisionBinData = DecodeBlob(blobGz);
            p.Bundle = ReadBundle(bundle);

            // The CA the tunnel will trust must be the one the SIGNED tenant document names. A portal
            // that could substitute its own CA could stand up its own concentrator.
            var caDer = Pem.FirstDer(Encoding.ASCII.GetString(p.Bundle["machine-ca-bundle.pem"]), "CERTIFICATE");
            if (caDer == null || Checks.Sha256Hex(caDer) != tenant.MachineCaSha256)
                throw new TrustException("the payload's machine CA is not the one the signed tenant document names");
            return p;
        }

        /// <summary>
        /// The blob file, as `djoin /savefile` writes it (FF FE, UTF-16LE base64, one NUL - measured,
        /// pat-platform RCA-53), gzipped, back to the BINARY provisioning data the API takes.
        /// </summary>
        public static byte[] DecodeBlob(byte[] blobGz)
        {
            byte[] file;
            using (var gz = new GZipStream(new MemoryStream(blobGz), CompressionMode.Decompress))
            using (var ms = new MemoryStream()) { gz.CopyTo(ms); file = ms.ToArray(); }
            if (file.Length < 1024 || file.Length % 2 != 0 || file[0] != 0xFF || file[1] != 0xFE)
                throw new TrustException("the join blob is not in the djoin file format (UTF-16LE with BOM)");
            var text = Encoding.Unicode.GetString(file, 2, file.Length - 2).TrimEnd('\0');
            try { return Convert.FromBase64String(text); }
            catch (FormatException e) { throw new TrustException("the join blob is not base64", e); }
        }

        private static IReadOnlyDictionary<string, byte[]> ReadBundle(byte[] zip)
        {
            var d = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            using (var z = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read))
            {
                foreach (var e in z.Entries)
                {
                    if (Array.IndexOf(BundleMembers, e.FullName) < 0)
                        throw new TrustException($"the certificate bundle holds an unexpected member '{e.FullName}'");
                    if (e.Length > 64 * 1024) throw new TrustException($"bundle member {e.FullName} is implausibly large");
                    using (var s = e.Open()) using (var ms = new MemoryStream()) { s.CopyTo(ms); d[e.FullName] = ms.ToArray(); }
                }
            }
            foreach (var m in BundleMembers)
                if (!d.ContainsKey(m)) throw new TrustException($"the certificate bundle has no {m}");
            return d;
        }
    }

    public static class Serials
    {
        /// <summary>BIOS serials are compared upper-case with all whitespace removed (as the portal stores them).</summary>
        public static string Normalise(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder(s.Length);
            foreach (var c in s) if (!char.IsWhiteSpace(c)) sb.Append(char.ToUpperInvariant(c));
            return sb.ToString();
        }
    }

    internal static class Pem
    {
        public static byte[] FirstDer(string pem, string kind)
        {
            string b = $"-----BEGIN {kind}-----", e = $"-----END {kind}-----";
            int i = pem?.IndexOf(b, StringComparison.Ordinal) ?? -1, j = i < 0 ? -1 : pem.IndexOf(e, i, StringComparison.Ordinal);
            if (i < 0 || j < 0) return null;
            var body = pem.Substring(i + b.Length, j - i - b.Length).Replace("\r", "").Replace("\n", "").Trim();
            try { return Convert.FromBase64String(body); } catch (FormatException) { return null; }
        }
    }
}
