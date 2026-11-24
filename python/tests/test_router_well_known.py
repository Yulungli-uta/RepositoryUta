def test_jwks_endpoint_returns_public_key_with_cache_header(client) -> None:
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "public, max-age=3600"
    key = response.json()["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
