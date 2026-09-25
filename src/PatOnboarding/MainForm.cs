using System;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
using Pat.Onboarding.Core;

namespace PatOnboarding
{
    internal sealed class MainForm : Form
    {
        private readonly TextBox _portal = new TextBox { Width = 380 };
        private readonly Button _start = new Button { Text = "Start", Width = 100 };
        private readonly Label _code = new Label { AutoSize = true, Font = new Font(FontFamily.GenericMonospace, 28, FontStyle.Bold), Visible = false };
        private readonly LinkLabel _link = new LinkLabel { AutoSize = true, Visible = false, Text = "Open the approval page" };
        private readonly ListBox _status = new ListBox { Width = 600, Height = 200, HorizontalScrollbar = true };
        private readonly Button _restart = new Button { Text = "Restart now", Width = 120, Visible = false };
        private Uri _approval;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        public MainForm(string portalArg)
        {
            Text = "PAT company laptop onboarding" + (TrustedKeys.IsDevelopmentKey ? "  [DEVELOPMENT BUILD]" : "");
            ClientSize = new Size(640, 420);
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; StartPosition = FormStartPosition.CenterScreen;
            var layout = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, Padding = new Padding(16), WrapContents = false };
            layout.Controls.Add(new Label { AutoSize = true, Text = "Company portal address (from IT):" });
            var row = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
            row.Controls.Add(_portal); row.Controls.Add(_start);
            layout.Controls.Add(row);
            layout.Controls.Add(_code); layout.Controls.Add(_link); layout.Controls.Add(_status); layout.Controls.Add(_restart);
            Controls.Add(layout);

            _portal.Text = portalArg ?? ConfiguredPortal() ?? "https://";
            _start.Click += async (s, e) => await StartAsync();
            _link.LinkClicked += (s, e) => { if (_approval != null) Onboarding.OpenBrowser(_approval); };
            _restart.Click += (s, e) => System.Diagnostics.Process.Start("shutdown.exe", "/r /t 5 /c \"Completing company laptop setup\"");
            FormClosing += (s, e) => _cts.Cancel();
        }

        /// <summary>The address IT deployed with the MSI (PORTAL_URL). Trust is still the tenant document's.</summary>
        private static string ConfiguredPortal()
        {
            try { using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\PAT\Onboarding")) return k?.GetValue("PortalUrl") as string; }
            catch { return null; }
        }

        private void Add(string m) => BeginInvoke((Action)(() => { _status.Items.Add(m); _status.TopIndex = _status.Items.Count - 1; }));

        private async System.Threading.Tasks.Task StartAsync()
        {
            if (!Uri.TryCreate(_portal.Text.Trim(), UriKind.Absolute, out var portal) || portal.Scheme != Uri.UriSchemeHttps)
            { MessageBox.Show(this, "Enter the https:// address IT gave you.", Text); return; }
            _start.Enabled = false; _portal.Enabled = false;
            var log = new Log();
            var ob = new Onboarding(portal, log);
            ob.Status += Add;
            ob.Waiting += () => BeginInvoke((Action)(() => { if (_status.Items.Count > 0 && ((string)_status.Items[_status.Items.Count - 1]).StartsWith("Waiting")) _status.Items[_status.Items.Count - 1] += "."; else _status.Items.Add("Waiting for approval"); }));
            ob.ShowCode += (code, uri) => BeginInvoke((Action)(() =>
            {
                _approval = uri; _code.Text = code; _code.Visible = true; _link.Visible = true;
                _status.Items.Add($"Your code is {code}. Sign in at {uri.Host} with your company account, check the laptop name and serial, and approve.");
                Onboarding.OpenBrowser(uri);
            }));
            try
            {
                var name = await ob.RunAsync(_cts.Token);
                Add($"Done. Restart, wait a minute at the sign-in screen, then sign in with your company account.");
                BeginInvoke((Action)(() => { _code.Visible = false; _link.Visible = false; _restart.Visible = true; }));
            }
            catch (TrustException e) { Fail("REFUSED - " + e.Message, log); }
            catch (PairingException e) { Fail(e.Message, log); }
            catch (Exception e) { Fail(e.Message, log); }
        }

        private void Fail(string m, Log log)
        {
            log.Write("ONBOARDING-FAILED: " + m);
            Add("FAILED: " + m);
            Add($"Nothing after this step was changed. Log: {log.Path}");
            BeginInvoke((Action)(() => { _code.Visible = false; _link.Visible = false; }));
        }
    }

    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            string portal = null;
            for (int i = 0; i < args.Length - 1; i++) if (args[i] == "--portal") portal = args[i + 1];
            if (!Machine.IsElevated()) { MessageBox.Show("Run as administrator.", "PAT onboarding"); return 2; }
            Application.EnableVisualStyles();
            Application.Run(new MainForm(portal));
            return 0;
        }
    }
}
