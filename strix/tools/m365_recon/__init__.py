"""Microsoft 365 / Azure AD (Entra ID) tenant enumeration.

Roadmap §7.3 expert-pentester gap audit. Probes the public Microsoft
endpoints that reveal whether a target uses M365 + the tenant ID +
federation posture (managed / federated / unknown). Reveals if SSO is
on, which IdP (ADFS / Okta / Ping), and the tenant ID — the pivot key
for any downstream Azure-resource probing.
"""

from .m365_recon import m365_tenant_recon


__all__ = ["m365_tenant_recon"]
