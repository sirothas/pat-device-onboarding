"""PAT's tenant-signing PUBLIC key, shipped in the package: the helper's only trust anchor for which
portals it will talk to. The same key as src/PatOnboarding/TrustedKeys.cs.

DEV KEY. Generated 2026-09-25 for development and the Hyper-V lab; its private half is held off-repo by
the operator. It MUST be replaced by the KMS-held production key before a signed public release - a
build that still trusts it is a development build, and says so.
"""
from .trust import TrustedKey

IS_DEVELOPMENT_KEY = True

CURRENT = TrustedKey(
    "pat-tenant-dev-2026-09",
    "ce8ad6549cba838f23c5f7a261ea9c2f4923083638b04832489e1f0231c54f16",
    "ead05ca68bf652cf1e712a01d52a4517865298f2e7f5a26dce02f55b821a5ef5",
)
