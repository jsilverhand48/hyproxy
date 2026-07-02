"""Phase 5 operational tooling: DDNS decision core and deployment seams.

ACME (DNS-01) and the TPM broker are deployment integrations (a vetted ACME
client such as lego/certbot feeding the data plane's cert hot-reload seam, and a
TPM unseal wired into TpmSecretsBackend); see docs/production.md. Only the pure,
provider-agnostic cores live here.
"""
