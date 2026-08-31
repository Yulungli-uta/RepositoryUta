import logging

import requests
from sqlalchemy.orm import Session

from repositoryuta.models.app_param import AppParam
from repositoryuta.schemas.license import (
    LicenseOperationResultRead,
    SubscribedSkuRead,
    UserLicenseRead,
)
from repositoryuta.services.graph_client import encode_path_segment, graph_request

logger = logging.getLogger(__name__)

# Espejo de MicrosoftLicenseService.cs. Prerequisito para asignar licencias:
# el usuario debe tener UsageLocation configurado (ver set_usage_location).

_EMPTY_GUID = "00000000-0000-0000-0000-000000000000"
_EMPLOYEE_LICENSE_NEMONIC = "lic:employee"


def _graph_error_message(response: requests.Response) -> str:
    """Espejo de `ex.Error?.Message ?? ex.Message` (ODataError)."""
    try:
        return response.json().get("error", {}).get("message") or response.text
    except ValueError:
        return response.text


# ── SKUs del tenant ──────────────────────────────────────────────────────────


def get_subscribed_skus() -> list[SubscribedSkuRead]:
    response = graph_request("GET", "/subscribedSkus")
    if not response.ok:
        msg = _graph_error_message(response)
        logger.error("Graph error al consultar subscribedSkus: %s", msg)
        raise RuntimeError(f"Error al consultar SKUs del tenant: {msg}")

    result = []
    for s in response.json().get("value", []):
        prepaid = (s.get("prepaidUnits") or {}).get("enabled")
        consumed = s.get("consumedUnits")
        result.append(
            SubscribedSkuRead(
                sku_id=s.get("skuId") or _EMPTY_GUID,
                sku_part_number=s.get("skuPartNumber") or "",
                capability_status=s.get("capabilityStatus"),
                prepaid_units_enabled=prepaid,
                consumed_units=consumed,
                available_units=(prepaid or 0) - (consumed or 0),
            )
        )
    return result


def get_sku_id_by_part_number(sku_part_number: str) -> str | None:
    skus = get_subscribed_skus()
    match = next(
        (s for s in skus if s.sku_part_number.lower() == sku_part_number.lower()), None
    )
    if match is None or match.sku_id == _EMPTY_GUID:
        return None
    return match.sku_id


# ── Licencias del usuario ────────────────────────────────────────────────────


def get_user_licenses(upn: str) -> list[UserLicenseRead]:
    response = graph_request("GET", f"/users/{encode_path_segment(upn)}/licenseDetails")
    if response.status_code == 404:
        logger.warning("Usuario %s no encontrado en Entra al consultar licencias", upn)
        return []
    if not response.ok:
        msg = _graph_error_message(response)
        logger.error("Graph error al consultar licencias de %s: %s", upn, msg)
        raise RuntimeError(f"Error al consultar licencias del usuario: {msg}")

    return [
        UserLicenseRead(
            sku_id=d.get("skuId") or _EMPTY_GUID, sku_part_number=d.get("skuPartNumber")
        )
        for d in response.json().get("value", [])
    ]


# ── Asignar licencia ──────────────────────────────────────────────────────────


def assign_license(
    upn: str, sku_part_number: str, country_code: str = "EC"
) -> LicenseOperationResultRead:
    try:
        sku_id = get_sku_id_by_part_number(sku_part_number)
        if sku_id is None:
            return LicenseOperationResultRead(
                success=False,
                upn=upn,
                sku_part_number=sku_part_number,
                sku_id=None,
                message=f"SKU '{sku_part_number}' no encontrado en los SKUs del tenant",
            )

        skus = get_subscribed_skus()
        sku = next((s for s in skus if s.sku_id == sku_id), None)
        if sku is not None and (sku.available_units or 0) <= 0:
            return LicenseOperationResultRead(
                success=False,
                upn=upn,
                sku_part_number=sku_part_number,
                sku_id=sku_id,
                message=(
                    f"Sin licencias disponibles para '{sku_part_number}' "
                    f"(disponibles: {sku.available_units})"
                ),
            )

        if country_code and country_code.strip():
            set_usage_location(upn, country_code)

        response = graph_request(
            "POST",
            f"/users/{encode_path_segment(upn)}/assignLicense",
            json={"addLicenses": [{"skuId": sku_id}], "removeLicenses": []},
        )
        if response.status_code == 404:
            msg = f"Usuario '{upn}' no encontrado en Entra. ¿Ya sincronizó con Entra Connect?"
            logger.warning("%s", msg)
            return LicenseOperationResultRead(
                success=False, upn=upn, sku_part_number=sku_part_number, sku_id=None, message=msg
            )
        if not response.ok:
            msg = _graph_error_message(response)
            logger.error(
                "Graph error al asignar licencia %s a %s: %s", sku_part_number, upn, msg
            )
            return LicenseOperationResultRead(
                success=False, upn=upn, sku_part_number=sku_part_number, sku_id=None, message=msg
            )

        logger.info("Licencia %s asignada a %s", sku_part_number, upn)
        return LicenseOperationResultRead(
            success=True,
            upn=upn,
            sku_part_number=sku_part_number,
            sku_id=sku_id,
            message=f"Licencia '{sku_part_number}' asignada exitosamente",
        )
    except Exception as exc:
        logger.error("Error al asignar licencia %s a %s: %s", sku_part_number, upn, exc)
        return LicenseOperationResultRead(
            success=False, upn=upn, sku_part_number=sku_part_number, sku_id=None, message=str(exc)
        )


# ── Quitar licencia ───────────────────────────────────────────────────────────


def remove_license(upn: str, sku_part_number: str) -> LicenseOperationResultRead:
    """A diferencia de assign_license, el .NET original (RemoveLicenseAsync) NO
    tiene un catch(Exception) generico — solo captura errores de Graph
    (ODataError). Un fallo no relacionado con Graph se propaga sin capturar y
    termina en un 500 generico; se replica ese comportamiento aqui a proposito
    (no envolver esta funcion en un try/except amplio)."""
    sku_id = get_sku_id_by_part_number(sku_part_number)
    if sku_id is None:
        return LicenseOperationResultRead(
            success=False,
            upn=upn,
            sku_part_number=sku_part_number,
            sku_id=None,
            message=f"SKU '{sku_part_number}' no encontrado en los SKUs del tenant",
        )

    response = graph_request(
        "POST",
        f"/users/{encode_path_segment(upn)}/assignLicense",
        json={"addLicenses": [], "removeLicenses": [sku_id]},
    )
    if response.status_code == 404:
        return LicenseOperationResultRead(
            success=False,
            upn=upn,
            sku_part_number=sku_part_number,
            sku_id=None,
            message=f"Usuario '{upn}' no encontrado en Entra",
        )
    if not response.ok:
        msg = _graph_error_message(response)
        logger.error("Graph error al remover licencia %s de %s: %s", sku_part_number, upn, msg)
        return LicenseOperationResultRead(
            success=False, upn=upn, sku_part_number=sku_part_number, sku_id=None, message=msg
        )

    logger.info("Licencia %s removida de %s", sku_part_number, upn)
    return LicenseOperationResultRead(
        success=True,
        upn=upn,
        sku_part_number=sku_part_number,
        sku_id=sku_id,
        message=f"Licencia '{sku_part_number}' removida exitosamente",
    )


# ── Asignar licencia de empleado (SKU único para todos los empleados) ────────


def assign_employee_license(
    session: Session, upn: str, country_code: str = "EC"
) -> LicenseOperationResultRead:
    param = session.get(AppParam, _EMPLOYEE_LICENSE_NEMONIC)
    if param is None or not param.value.strip():
        msg = (
            f"No hay SKU de empleado configurado. Configure AppParam "
            f"'{_EMPLOYEE_LICENSE_NEMONIC}' con el SkuPartNumber del tenant."
        )
        logger.warning("%s", msg)
        return LicenseOperationResultRead(
            success=False, upn=upn, sku_part_number=None, sku_id=None, message=msg
        )

    return assign_license(upn, param.value, country_code)


# ── UsageLocation ─────────────────────────────────────────────────────────────


def set_usage_location(upn: str, country_code: str) -> None:
    response = graph_request(
        "PATCH",
        f"/users/{encode_path_segment(upn)}",
        json={"usageLocation": country_code.upper()},
    )
    if response.status_code == 404:
        raise RuntimeError(f"Usuario '{upn}' no encontrado en Entra al configurar UsageLocation")
    if not response.ok:
        msg = _graph_error_message(response)
        logger.error("Graph error al configurar UsageLocation para %s: %s", upn, msg)
        raise RuntimeError(f"Error al configurar UsageLocation: {msg}")

    logger.info("UsageLocation=%s configurado para %s", country_code, upn)
