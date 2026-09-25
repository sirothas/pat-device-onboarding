using System;
using Pat.Onboarding.Core;

namespace PatOnboarding
{
    /// <summary>
    /// PAT's tenant-signing PUBLIC keys, compiled in: the installer's only trust anchor for which
    /// portals it will talk to (ADR 0057 phases 2-3, section 1). A public key is not a secret; that
    /// it is compiled in (and covered by the code signature) is what matters.
    ///
    /// DEV KEY. Generated 2026-09-25 for development and the Hyper-V lab; its private half is held
    /// off-repo by the operator. It MUST be replaced by the KMS-held production key before a signed
    /// public release - a build that still trusts it is a development build, and says so in its title.
    /// </summary>
    internal static class TrustedKeys
    {
        public const bool IsDevelopmentKey = true;

        public static TrustedKey Current => new TrustedKey(
            "pat-tenant-dev-2026-09",
            Hex("ce8ad6549cba838f23c5f7a261ea9c2f4923083638b04832489e1f0231c54f16"),
            Hex("ead05ca68bf652cf1e712a01d52a4517865298f2e7f5a26dce02f55b821a5ef5"));

        private static byte[] Hex(string h)
        {
            var b = new byte[h.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
            return b;
        }
    }
}
