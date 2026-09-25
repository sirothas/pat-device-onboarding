using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Pat.Onboarding.Core;

namespace PatOnboarding
{
    /// <summary>
    /// The whole onboarding, in the proven order (ADR 0056): verify everything first, TUNNEL before
    /// JOIN (a tunnel without a join is harmless and retryable; a join without a tunnel boots into the
    /// ten-minute no-DC state), and nothing secret written anywhere except config-auto.
    /// </summary>
    internal sealed class Onboarding
    {
        public event Action<string> Status;
        public event Action<string, Uri> ShowCode;
        public event Action Waiting;

        private readonly Uri _portal;
        private readonly Log _log;

        public Onboarding(Uri portal, Log log) { _portal = portal; _log = log; }

        private void Say(string m) { _log.Write(m); Status?.Invoke(m); }

        public async Task<string> RunAsync(CancellationToken ct)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            // 1. this machine - read from the OS
            if (!Machine.IsElevated()) throw new InvalidOperationException("not running elevated");
            if (Machine.IsDomainJoined(out var dom)) throw new InvalidOperationException($"this laptop is already joined to {dom}");
            var serial = Machine.BiosSerial();
            Say($"This laptop's serial number: {serial}");
            var tunnel = new Tunnel();
            tunnel.PreFlight();

            // 2. the portal - believed only with PAT's signature, and only for itself
            var client = new PairingClient(_portal);
            var tenant = TenantDocument.Verify(await client.GetTenantEnvelopeAsync(ct).ConfigureAwait(false),
                                               TrustedKeys.Current, _portal, DateTimeOffset.UtcNow);
            Say($"Portal verified: {tenant.Portal.Host} (tenant {tenant.Tenant}, signed by PAT)");

            // 3. pairing - the employee approves this laptop in the portal
            var started = await client.StartAsync(serial, ct).ConfigureAwait(false);
            _log.Write($"pairing started, code {started.UserCode}");   // the user code is shown on screen anyway; the device code is never logged
            ShowCode?.Invoke(started.UserCode, started.VerificationUriComplete);
            var token = await client.PollAsync(started, () => Waiting?.Invoke(), ct).ConfigureAwait(false);

            // 4. the payload - bound to this machine and this tenant before anything is touched
            var payload = Payload.Accept(token, serial, tenant);
            token = null;
            Say($"Approved - received the configuration for {payload.Name}");

            // 5. tunnel first
            Say("Installing the secure connection that starts before sign-in...");
            tunnel.Install(payload);
            Say("Secure connection installed.");

            // 6. join second
            Say($"Joining this laptop to the company domain as {payload.Name}...");
            OfflineJoin.Apply(payload.ProvisionBinData);
            Say("Domain join staged. It takes effect when you restart.");
            _log.Write("ONBOARDING-OK");
            return payload.Name;
        }

        public static void OpenBrowser(Uri u)
        {
            try { Process.Start(new ProcessStartInfo(u.AbsoluteUri) { UseShellExecute = true }); } catch { /* the code is on screen */ }
        }
    }

    /// <summary>Plain-text log under ProgramData. Never a secret: no device code, no payload, no key.</summary>
    internal sealed class Log
    {
        public readonly string Path;
        public Log()
        {
            var dir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"PAT\Onboarding\logs");
            Directory.CreateDirectory(dir);
            Path = System.IO.Path.Combine(dir, $"onboarding-{DateTime.UtcNow:yyyyMMddTHHmmssZ}.log");
        }
        public void Write(string m)
        {
            try { File.AppendAllText(Path, $"{DateTime.UtcNow:u} {m}{Environment.NewLine}"); } catch { }
        }
    }
}
