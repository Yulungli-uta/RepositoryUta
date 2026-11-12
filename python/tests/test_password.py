import hashlib

from repositoryuta.core.security.password import hash_password, verify_password


def test_bcrypt_roundtrip() -> None:
    hashed = hash_password("Sup3rSecret!")

    assert hashed.startswith("$2")
    assert verify_password("Sup3rSecret!", hashed)
    assert not verify_password("wrong", hashed)


def test_legacy_sha256_fallback_matches_dotnet_format() -> None:
    # Utilities/PasswordHasher.cs compara Convert.ToHexString(...) (mayusculas) de
    # forma case-insensitive: se prueba con mayusculas para no dar por hecho el casing.
    legacy_hash = hashlib.sha256(b"OldPassword1").hexdigest().upper()

    assert verify_password("OldPassword1", legacy_hash)
    assert not verify_password("wrong", legacy_hash)


def test_garbage_hash_is_rejected() -> None:
    assert not verify_password("whatever", "not-a-real-hash")
