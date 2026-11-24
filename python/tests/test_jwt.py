import jwt as pyjwt
import pytest

from repositoryuta.core.security.jwt import (
    CLAIM_NAME_IDENTIFIER,
    create_app_token,
    create_user_token,
    decode_token,
    get_jwks,
    roles_from_payload,
)


def test_user_token_roundtrip() -> None:
    token = create_user_token(
        "user-1", "juan.perez@uta.edu.ec", ["R_EMPLOYEE", "R_RH"], employee_id=123
    )

    payload = decode_token(token)

    assert payload["sub"] == "user-1"
    assert payload["email"] == "juan.perez@uta.edu.ec"
    assert payload[CLAIM_NAME_IDENTIFIER] == "user-1"
    assert roles_from_payload(payload) == ["R_EMPLOYEE", "R_RH"]
    assert payload["employeeId"] == 123


def test_app_token_roundtrip_has_no_user_claims() -> None:
    token = create_app_token(
        "token-1", "uta-signature", ["R_SIGNATURE_INTEGRATION"], lifetime_minutes=60
    )

    payload = decode_token(token)

    assert payload["client_id"] == "uta-signature"
    assert payload["token_use"] == "app"
    assert "email" not in payload
    assert CLAIM_NAME_IDENTIFIER not in payload


def test_jwks_exposes_public_key_material() -> None:
    jwks = get_jwks()

    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert "n" in key
    assert "e" in key


def test_decode_rejects_tampered_token() -> None:
    token = create_user_token("user-1", "x@uta.edu.ec", [])

    with pytest.raises(pyjwt.InvalidTokenError):
        decode_token(token + "tampered")
