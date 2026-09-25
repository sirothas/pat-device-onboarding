using System;
using System.Text;

namespace Pat.Onboarding.Core
{
    /// <summary>
    /// The machine-tunnel OpenVPN profile - the same directives as the proven PowerShell installer
    /// (pat-platform Install-OdjDevice.ps1), so the concentrator sees the same client. File names are
    /// the ones the profile references inside config-auto.
    /// </summary>
    public static class TunnelProfile
    {
        public const string CaFile = "machine-ca.pem";
        public const string CertFile = "machine-client.crt";
        public const string KeyFile = "machine-client.key";
        public const string TlsCryptFile = "machine-tc.key";
        public const string ProfileFile = "machine.ovpn";

        /// <summary>bundle member name -> the name it is installed under in config-auto.</summary>
        public static string InstalledName(string bundleMember)
        {
            switch (bundleMember)
            {
                case "machine.crt": return CertFile;
                case "machine.key": return KeyFile;
                case "machine-ca-bundle.pem": return CaFile;
                case "machine-tc.key": return TlsCryptFile;
                default: throw new ArgumentException($"not a bundle member: {bundleMember}");
            }
        }

        public static string Render(string server, int port, int tunMtu)
        {
            if (!Checks.IsHostName(server)) throw new ArgumentException("server is not a host name");
            // remote-cert-eku pins the SERVER's purpose and verify-x509-name its identity: a client
            // certificate presented by an impostor, or another host's certificate, is refused.
            var sb = new StringBuilder();
            foreach (var line in new[] {
                "client", "dev tun", "proto udp", $"remote {server} {port}", "resolv-retry infinite", "nobind",
                "persist-key", "persist-tun", $"ca {CaFile}", $"cert {CertFile}", $"key {KeyFile}",
                $"tls-crypt {TlsCryptFile}", "remote-cert-eku \"TLS Web Server Authentication\"",
                $"verify-x509-name {server} name", "cipher AES-256-GCM", "data-ciphers AES-256-GCM",
                $"tun-mtu {tunMtu}", "verb 4" })
                sb.Append(line).Append("\r\n");
            return sb.ToString();
        }
    }
}
