"""py_webauthn wrapper: registration and assertion for passkey-tier users.

The RP ID and origin derive from the issuer URL; assertions are origin-bound,
which is what makes this tier phishing-resistant.
"""

import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from hyproxy.config import get_settings
from hyproxy.db.models import User, WebAuthnCredential


def rp_id() -> str:
    host = urlsplit(get_settings().issuer).hostname
    assert host is not None
    return host


def expected_origin() -> str:
    parts = urlsplit(get_settings().issuer)
    return f"{parts.scheme}://{parts.netloc}"


def registration_options_json(user: User, existing: list[WebAuthnCredential]) -> tuple[str, bytes]:
    """Returns (options_json, challenge). Challenge must be persisted server-side."""
    options = generate_registration_options(
        rp_id=rp_id(),
        rp_name="hyproxy",
        user_id=user.external_id.encode(),
        user_name=user.email,
        user_display_name=user.display_name,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=cred.credential_id) for cred in existing
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return options_to_json(options), options.challenge


@dataclass(frozen=True)
class RegistrationResult:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    aaguid: uuid.UUID | None


def verify_registration(credential_json: str, challenge: bytes) -> RegistrationResult:
    """Raises webauthn.helpers.exceptions.InvalidRegistrationResponse on failure."""
    verified = verify_registration_response(
        credential=credential_json,
        expected_challenge=challenge,
        expected_rp_id=rp_id(),
        expected_origin=expected_origin(),
        require_user_verification=False,
    )
    aaguid: uuid.UUID | None
    try:
        aaguid = uuid.UUID(verified.aaguid)
    except (ValueError, TypeError):
        aaguid = None
    return RegistrationResult(
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        aaguid=aaguid,
    )


def authentication_options_json(
    credentials: list[WebAuthnCredential],
) -> tuple[str, bytes]:
    """Returns (options_json, challenge)."""
    options = generate_authentication_options(
        rp_id=rp_id(),
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=cred.credential_id) for cred in credentials
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return options_to_json(options), options.challenge


def verify_assertion(credential_json: str, challenge: bytes, credential: WebAuthnCredential) -> int:
    """Returns the new sign count. Raises InvalidAuthenticationResponse on failure."""
    verified = verify_authentication_response(
        credential=credential_json,
        expected_challenge=challenge,
        expected_rp_id=rp_id(),
        expected_origin=expected_origin(),
        credential_public_key=credential.public_key,
        credential_current_sign_count=credential.sign_count,
        require_user_verification=False,
    )
    return verified.new_sign_count
