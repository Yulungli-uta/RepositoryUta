import pytest

from repositoryuta.models.app_param import AppParam
from repositoryuta.services import license_service as svc


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None, text: str = "") -> None:
        self.status_code = status_code
        self.ok = status_code < 400
        self._payload = payload or {}
        self.text = text or str(payload or "")

    def json(self) -> dict:
        return self._payload


def _patch_graph(monkeypatch: pytest.MonkeyPatch, responder) -> list[tuple]:
    calls: list[tuple] = []

    def _fake(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return responder(method, path, kwargs)

    monkeypatch.setattr(svc, "graph_request", _fake)
    return calls


_SKU_PAYLOAD = {
    "value": [
        {
            "skuId": "11111111-1111-1111-1111-111111111111",
            "skuPartNumber": "STANDARDWOFFPACK_FACULTY",
            "capabilityStatus": "Enabled",
            "prepaidUnits": {"enabled": 100},
            "consumedUnits": 40,
        },
        {
            "skuId": "22222222-2222-2222-2222-222222222222",
            "skuPartNumber": "AGOTADO_SKU",
            "capabilityStatus": "Enabled",
            "prepaidUnits": {"enabled": 5},
            "consumedUnits": 5,
        },
    ]
}


# ── get_subscribed_skus ──────────────────────────────────────────────────────


def test_get_subscribed_skus_maps_available_units(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, _SKU_PAYLOAD))

    skus = svc.get_subscribed_skus()

    assert len(skus) == 2
    assert skus[0].available_units == 60
    assert skus[1].available_units == 0


def test_get_subscribed_skus_raises_on_graph_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(
        monkeypatch,
        lambda m, p, k: _FakeResponse(500, {"error": {"message": "boom"}}),
    )

    with pytest.raises(RuntimeError, match="boom"):
        svc.get_subscribed_skus()


# ── get_sku_id_by_part_number ────────────────────────────────────────────────


def test_get_sku_id_by_part_number_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, _SKU_PAYLOAD))

    sku_id = svc.get_sku_id_by_part_number("standardwoffpack_faculty")

    assert sku_id == "11111111-1111-1111-1111-111111111111"


def test_get_sku_id_by_part_number_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, _SKU_PAYLOAD))

    assert svc.get_sku_id_by_part_number("NO_EXISTE") is None


def test_get_sku_id_by_part_number_treats_empty_guid_as_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {"value": [{"skuPartNumber": "SIN_GUID", "prepaidUnits": {"enabled": 1}}]}
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, payload))

    assert svc.get_sku_id_by_part_number("SIN_GUID") is None


# ── get_user_licenses ────────────────────────────────────────────────────────


def test_get_user_licenses_success(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"value": [{"skuId": "11111111-1111-1111-1111-111111111111", "skuPartNumber": "X"}]}
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, payload))

    licenses = svc.get_user_licenses("juan@uta.edu.ec")

    assert len(licenses) == 1
    assert licenses[0].sku_part_number == "X"


def test_get_user_licenses_returns_empty_on_404(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(404))

    assert svc.get_user_licenses("no-existe@uta.edu.ec") == []


def test_get_user_licenses_raises_on_other_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(500, {"error": {"message": "boom"}}))

    with pytest.raises(RuntimeError, match="boom"):
        svc.get_user_licenses("juan@uta.edu.ec")


# ── assign_license ───────────────────────────────────────────────────────────


def test_assign_license_sku_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, {"value": []}))

    result = svc.assign_license("juan@uta.edu.ec", "NO_EXISTE")

    assert result.success is False
    assert "no encontrado en los SKUs" in result.message


def test_assign_license_no_available_units(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, _SKU_PAYLOAD))

    result = svc.assign_license("juan@uta.edu.ec", "AGOTADO_SKU")

    assert result.success is False
    assert "Sin licencias disponibles" in result.message


def test_assign_license_success_sets_usage_location_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_graph(
        monkeypatch,
        lambda m, p, k: _FakeResponse(200, _SKU_PAYLOAD) if m == "GET" else _FakeResponse(200, {}),
    )

    result = svc.assign_license("juan@uta.edu.ec", "STANDARDWOFFPACK_FACULTY", "ec")

    assert result.success is True
    assert result.sku_id == "11111111-1111-1111-1111-111111111111"
    methods_paths = [(c[0], c[1]) for c in calls]
    assert ("PATCH", "/users/juan%40uta.edu.ec") in methods_paths
    assert ("POST", "/users/juan%40uta.edu.ec/assignLicense") in methods_paths
    patch_index = methods_paths.index(("PATCH", "/users/juan%40uta.edu.ec"))
    post_index = methods_paths.index(("POST", "/users/juan%40uta.edu.ec/assignLicense"))
    assert patch_index < post_index


def test_assign_license_skips_usage_location_when_country_code_blank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch_graph(
        monkeypatch,
        lambda m, p, k: _FakeResponse(200, _SKU_PAYLOAD) if m == "GET" else _FakeResponse(200, {}),
    )

    result = svc.assign_license("juan@uta.edu.ec", "STANDARDWOFFPACK_FACULTY", "  ")

    assert result.success is True
    assert all(c[0] != "PATCH" for c in calls)


def test_assign_license_user_not_found_returns_specific_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _responder(method, path, kwargs):
        if method == "GET":
            return _FakeResponse(200, _SKU_PAYLOAD)
        if method == "PATCH":
            return _FakeResponse(200, {})
        return _FakeResponse(404)

    _patch_graph(monkeypatch, _responder)

    result = svc.assign_license("nadie@uta.edu.ec", "STANDARDWOFFPACK_FACULTY")

    assert result.success is False
    assert "Entra Connect" in result.message


def test_assign_license_catches_any_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(method, path, **kwargs):
        raise ConnectionError("red caída")

    monkeypatch.setattr(svc, "graph_request", _raise)

    result = svc.assign_license("juan@uta.edu.ec", "STANDARDWOFFPACK_FACULTY")

    assert result.success is False
    assert "red caída" in result.message


def test_assign_license_escapes_upn_in_graph_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un upn con '/' no debe alterar la ruta real enviada a Graph (ver
    graph_client.encode_path_segment) — a diferencia del SDK .NET, aqui la URL
    se arma a mano y sin esto un valor como 'a/subscribedSkus' inyectaria un
    segmento de path distinto."""
    calls = _patch_graph(
        monkeypatch,
        lambda m, p, k: _FakeResponse(200, _SKU_PAYLOAD) if m == "GET" else _FakeResponse(200, {}),
    )

    svc.assign_license("a/b@uta.edu.ec", "STANDARDWOFFPACK_FACULTY", "")

    paths = [c[1] for c in calls]
    assert any(p == "/users/a%2Fb%40uta.edu.ec/assignLicense" for p in paths)
    assert not any("/b@uta.edu.ec" in p and p.count("/") > 2 for p in paths)


# ── remove_license ───────────────────────────────────────────────────────────


def test_remove_license_sku_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, {"value": []}))

    result = svc.remove_license("juan@uta.edu.ec", "NO_EXISTE")

    assert result.success is False


def test_remove_license_success(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(
        monkeypatch,
        lambda m, p, k: _FakeResponse(200, _SKU_PAYLOAD) if m == "GET" else _FakeResponse(200, {}),
    )

    result = svc.remove_license("juan@uta.edu.ec", "STANDARDWOFFPACK_FACULTY")

    assert result.success is True


def test_remove_license_user_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(
        monkeypatch,
        lambda m, p, k: _FakeResponse(200, _SKU_PAYLOAD) if m == "GET" else _FakeResponse(404),
    )

    result = svc.remove_license("nadie@uta.edu.ec", "STANDARDWOFFPACK_FACULTY")

    assert result.success is False
    assert "no encontrado en Entra" in result.message


def test_remove_license_does_not_swallow_non_graph_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise(method, path, **kwargs):
        raise ConnectionError("red caída")

    monkeypatch.setattr(svc, "graph_request", _raise)

    with pytest.raises(ConnectionError):
        svc.remove_license("juan@uta.edu.ec", "STANDARDWOFFPACK_FACULTY")


# ── assign_employee_license ──────────────────────────────────────────────────


def test_assign_employee_license_no_param_configured(sqlite_session) -> None:
    result = svc.assign_employee_license(sqlite_session, "juan@uta.edu.ec")

    assert result.success is False
    assert "AppParam" in result.message


def test_assign_employee_license_delegates_to_assign_license(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    sqlite_session.add(AppParam(nemonic="lic:employee", value="STANDARDWOFFPACK_FACULTY"))
    sqlite_session.commit()

    captured = {}

    def _fake_assign(upn, sku_part_number, country_code="EC"):
        captured["args"] = (upn, sku_part_number, country_code)
        return svc.LicenseOperationResultRead(
            success=True, upn=upn, sku_part_number=sku_part_number, sku_id="x", message="ok"
        )

    monkeypatch.setattr(svc, "assign_license", _fake_assign)

    result = svc.assign_employee_license(sqlite_session, "juan@uta.edu.ec", "PE")

    assert result.success is True
    assert captured["args"] == ("juan@uta.edu.ec", "STANDARDWOFFPACK_FACULTY", "PE")


# ── set_usage_location ───────────────────────────────────────────────────────


def test_set_usage_location_success(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, {}))

    svc.set_usage_location("juan@uta.edu.ec", "ec")

    assert calls[0][2]["json"]["usageLocation"] == "EC"


def test_set_usage_location_raises_on_404(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(404))

    with pytest.raises(RuntimeError, match="no encontrado en Entra"):
        svc.set_usage_location("nadie@uta.edu.ec", "EC")


def test_set_usage_location_raises_on_graph_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(500, {"error": {"message": "boom"}}))

    with pytest.raises(RuntimeError, match="boom"):
        svc.set_usage_location("juan@uta.edu.ec", "EC")
