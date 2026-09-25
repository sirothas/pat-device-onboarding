using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Pat.Onboarding.Core
{
    /// <summary>
    /// The installer's half of the device-code pairing (RFC 8628 shape; IIP /odj/pair and
    /// /odj/pair/token). The device code is a bearer secret held only in this object's memory.
    /// </summary>
    public sealed class PairingClient
    {
        private readonly HttpClient _http;
        private readonly Uri _portal;

        public PairingClient(Uri portal, HttpMessageHandler handler = null)
        {
            if (portal == null || portal.Scheme != Uri.UriSchemeHttps) throw new ArgumentException("the portal must be https");
            _portal = portal;
            _http = handler == null ? new HttpClient() : new HttpClient(handler);
            _http.Timeout = TimeSpan.FromSeconds(30);
        }

        public async Task<string> GetTenantEnvelopeAsync(CancellationToken ct)
        {
            using (var r = await _http.GetAsync(new Uri(_portal, "/.well-known/pat-onboarding.json"), ct).ConfigureAwait(false))
            {
                if (r.StatusCode != HttpStatusCode.OK)
                    throw new TrustException($"the portal has no PAT tenant document (HTTP {(int)r.StatusCode}) - it is not an enrolled portal");
                return await r.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
        }

        public sealed class Started
        {
            public string DeviceCode;
            public string UserCode;
            public Uri VerificationUri;
            public Uri VerificationUriComplete;
            public int ExpiresIn;
            public int Interval;
        }

        public async Task<Started> StartAsync(string serial, CancellationToken ct)
        {
            var body = new StringContent(JsonSerializer.Serialize(new { serial }), Encoding.UTF8, "application/json");
            using (var r = await _http.PostAsync(new Uri(_portal, "/odj/pair"), body, ct).ConfigureAwait(false))
            {
                var text = await r.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (r.StatusCode != HttpStatusCode.OK) throw new PairingException(Error(text) ?? $"HTTP {(int)r.StatusCode}", text);
                using (var d = JsonDocument.Parse(text))
                {
                    var e = d.RootElement;
                    var s = new Started
                    {
                        DeviceCode = e.GetProperty("device_code").GetString(),
                        UserCode = e.GetProperty("user_code").GetString(),
                        VerificationUri = new Uri(e.GetProperty("verification_uri").GetString()),
                        VerificationUriComplete = new Uri(e.GetProperty("verification_uri_complete").GetString()),
                        ExpiresIn = e.GetProperty("expires_in").GetInt32(),
                        Interval = Math.Max(2, e.GetProperty("interval").GetInt32()),
                    };
                    // The approval page must be on the SAME portal the tenant document vouched for -
                    // a portal that sent the employee elsewhere to approve is not one to trust.
                    if (!string.Equals(s.VerificationUri.Host, _portal.Host, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(s.VerificationUriComplete.Host, _portal.Host, StringComparison.OrdinalIgnoreCase))
                        throw new TrustException("the portal's approval link points at a different host");
                    return s;
                }
            }
        }

        /// <summary>
        /// Poll until approved. Returns the token response JSON (the payload) once; throws on
        /// expiry or denial. RFC 8628 3.5: authorization_pending keeps waiting, slow_down backs off.
        /// </summary>
        public async Task<string> PollAsync(Started s, Action onWaiting, CancellationToken ct)
        {
            var deadline = DateTimeOffset.UtcNow.AddSeconds(s.ExpiresIn + 30);
            var interval = s.Interval;
            while (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(TimeSpan.FromSeconds(interval), ct).ConfigureAwait(false);
                var body = new StringContent(JsonSerializer.Serialize(new { device_code = s.DeviceCode }), Encoding.UTF8, "application/json");
                using (var r = await _http.PostAsync(new Uri(_portal, "/odj/pair/token"), body, ct).ConfigureAwait(false))
                {
                    var text = await r.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (r.StatusCode == HttpStatusCode.OK) { s.DeviceCode = null; return text; }
                    switch (Error(text))
                    {
                        case "authorization_pending": onWaiting?.Invoke(); continue;
                        case "slow_down": interval += 5; continue;
                        case "expired_token": throw new PairingException("the code expired before it was approved - start again", text);
                        case "access_denied": throw new PairingException("the portal refused to release this laptop's configuration (already delivered, or not assigned to you) - ask IT", text);
                        default: throw new PairingException($"unexpected answer from the portal (HTTP {(int)r.StatusCode})", text);
                    }
                }
            }
            throw new PairingException("no approval before the code expired - start again", null);
        }

        private static string Error(string json)
        {
            try { using (var d = JsonDocument.Parse(json)) return d.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null; }
            catch (JsonException) { return null; }
        }
    }

    public sealed class PairingException : Exception
    {
        public string Body { get; }
        public PairingException(string m, string body) : base(m) { Body = body; }
    }
}
