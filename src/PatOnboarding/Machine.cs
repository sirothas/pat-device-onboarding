using System;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Pat.Onboarding.Core;

namespace PatOnboarding
{
    /// <summary>This machine's facts, read from the OS - never from the portal or the user.</summary>
    internal static class Machine
    {
        public static string BiosSerial()
        {
            using (var s = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"))
                foreach (ManagementObject o in s.Get())
                    return Serials.Normalise(o["SerialNumber"] as string);
            throw new InvalidOperationException("Win32_BIOS reported no serial number");
        }

        public static bool IsDomainJoined(out string domainOrWorkgroup)
        {
            using (var s = new ManagementObjectSearcher("SELECT PartOfDomain, Domain FROM Win32_ComputerSystem"))
                foreach (ManagementObject o in s.Get())
                {
                    domainOrWorkgroup = o["Domain"] as string;
                    return (bool)o["PartOfDomain"];
                }
            throw new InvalidOperationException("Win32_ComputerSystem is unavailable");
        }

        public static bool IsElevated() =>
            new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// The machine tunnel: profile + credentials into OpenVPN's config-auto (started by OpenVPNService
    /// as its service account at BOOT, before logon - config\ would only start after logon), with a
    /// DACL of exactly SYSTEM, Administrators and the service account (read). Ported from the proven
    /// Install-OdjDevice.ps1, including both directions of the ACL check (#166).
    /// </summary>
    internal sealed class Tunnel
    {
        public readonly string OpenVpnRoot;
        public string ConfigAuto => Path.Combine(OpenVpnRoot, "config-auto");
        public string ConfigUser => Path.Combine(OpenVpnRoot, "config");

        public Tunnel(string openVpnRoot = null)
        {
            OpenVpnRoot = openVpnRoot ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OpenVPN");
        }

        public void PreFlight()
        {
            if (!File.Exists(Path.Combine(OpenVpnRoot, @"bin\openvpn.exe")))
                throw new InvalidOperationException($"OpenVPN is not installed under {OpenVpnRoot}");
            if (ServiceController.GetServices().All(s => s.ServiceName != "OpenVPNService"))
                throw new InvalidOperationException("OpenVPNService is not installed - config-auto would never be read");
            // Any other profile in config-auto starts its OWN tunnel at boot, beside the machine tunnel.
            if (Directory.Exists(ConfigAuto))
            {
                var foreign = Directory.GetFiles(ConfigAuto, "*.ovpn").Select(Path.GetFileName)
                                       .Where(n => !string.Equals(n, TunnelProfile.ProfileFile, StringComparison.OrdinalIgnoreCase)).ToArray();
                if (foreign.Length > 0)
                    throw new InvalidOperationException($"config-auto already holds other profile(s): {string.Join(", ", foreign)} - remove them first");
            }
        }

        public void Install(Payload p)
        {
            Directory.CreateDirectory(ConfigAuto);
            foreach (var m in Payload.BundleMembers)
                File.WriteAllBytes(Path.Combine(ConfigAuto, TunnelProfile.InstalledName(m)), p.Bundle[m]);
            File.WriteAllText(Path.Combine(ConfigAuto, TunnelProfile.ProfileFile), TunnelProfile.Render(p.Server, p.Port, p.TunMtu), System.Text.Encoding.ASCII);

            var svcAccount = ServiceAccount();
            SecurityIdentifier svcSid = IsLocalSystem(svcAccount) ? null
                : (SecurityIdentifier)new NTAccount(svcAccount).Translate(typeof(SecurityIdentifier));
            var sys = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adm = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            foreach (var f in Directory.GetFiles(ConfigAuto))
            {
                var acl = new FileSecurity();
                acl.SetAccessRuleProtection(true, false);
                acl.AddAccessRule(new FileSystemAccessRule(sys, FileSystemRights.FullControl, AccessControlType.Allow));
                acl.AddAccessRule(new FileSystemAccessRule(adm, FileSystemRights.FullControl, AccessControlType.Allow));
                // READ, not FullControl: openvpn.exe only reads its credentials.
                if (svcSid != null) acl.AddAccessRule(new FileSystemAccessRule(svcSid, FileSystemRights.Read, AccessControlType.Allow));
                File.SetAccessControl(f, acl);
            }

            // Read back from a FRESH enumeration - both directions: nothing broader, AND the service can read.
            var allowed = new[] { sys, adm, svcSid }.Where(x => x != null).ToArray();
            foreach (var f in Directory.GetFiles(ConfigAuto))
            {
                var back = File.GetAccessControl(f);
                if (!back.AreAccessRulesProtected) throw new InvalidOperationException($"{Path.GetFileName(f)} still inherits permissions");
                bool svcCanRead = svcSid == null;
                foreach (FileSystemAccessRule r in back.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (r.AccessControlType != AccessControlType.Allow) continue;
                    var sid = (SecurityIdentifier)r.IdentityReference;
                    if (!allowed.Contains(sid)) throw new InvalidOperationException($"{Path.GetFileName(f)} is readable by {sid} - beyond SYSTEM, Administrators and the OpenVPN service");
                    if (svcSid != null && sid == svcSid && (r.FileSystemRights & FileSystemRights.Read) == FileSystemRights.Read) svcCanRead = true;
                }
                if (!svcCanRead) throw new InvalidOperationException($"{svcAccount} cannot read {Path.GetFileName(f)} - the tunnel would restart-loop");
            }

            if (Directory.Exists(ConfigUser) && Directory.GetFiles(ConfigUser, "*.ovpn").Length > 0)
                throw new InvalidOperationException($"there are profiles in {ConfigUser} - a user-started tunnel would confound the machine tunnel");
            SetAutomatic("OpenVPNService");
        }

        private static string ServiceAccount()
        {
            using (var s = new ManagementObjectSearcher("SELECT StartName FROM Win32_Service WHERE Name='OpenVPNService'"))
                foreach (ManagementObject o in s.Get())
                {
                    var n = o["StartName"] as string;
                    if (!string.IsNullOrEmpty(n)) return n;
                }
            throw new InvalidOperationException("cannot read OpenVPNService's account - refusing to guess who needs the key");
        }

        private static bool IsLocalSystem(string a) =>
            a.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase) || a.Equals(@".\LocalSystem", StringComparison.OrdinalIgnoreCase) ||
            a.Equals(@"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase);

        private static void SetAutomatic(string name)
        {
            using (var mo = new ManagementObject($"Win32_Service.Name='{name}'"))
            {
                var r = (uint)mo.InvokeMethod("ChangeStartMode", new object[] { "Automatic" });
                if (r != 0) throw new InvalidOperationException($"could not set {name} to Automatic (WMI {r})");
            }
        }
    }

    /// <summary>
    /// The offline domain join, by the API djoin.exe wraps - with the BINARY provisioning data, so
    /// there is no blob file whose encoding could be wrong (pat-platform RCA-53).
    /// </summary>
    internal static class OfflineJoin
    {
        // "must be specified when calling against a running operating system"
        private const int NETSETUP_PROVISION_ONLINE_CALLER = 0x40000000;

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern int NetRequestOfflineDomainJoin(byte[] pProvisionBinData, int cbProvisionBinDataSize,
                                                              int dwOptions, string lpWindowsPath);

        public static void Apply(byte[] provisionBinData)
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var rc = NetRequestOfflineDomainJoin(provisionBinData, provisionBinData.Length, NETSETUP_PROVISION_ONLINE_CALLER, windows);
            Array.Clear(provisionBinData, 0, provisionBinData.Length);   // a machine account password
            if (rc != 0) throw new InvalidOperationException($"the offline domain join failed: {new System.ComponentModel.Win32Exception(rc).Message} (0x{rc:X})");
        }
    }
}
