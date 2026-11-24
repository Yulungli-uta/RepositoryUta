import logging
import unicodedata

from sqlalchemy.orm import Session

from repositoryuta.models.identity import ProvisioningStatus, User, UserProvisioning
from repositoryuta.services import local_ad_service

logger = logging.getLogger(__name__)

# Espejo de InstitutionalEmailGenerator.cs.

_MAX_ATTEMPTS = 100


def get_expected_domain(base_dn: str | None) -> str:
    """Espejo de GetExpectedDomain (duplicado en .NET dentro de
    InstitutionalEmailGenerator y EmployeeProvisioningService) — se comparte
    aqui una unica implementacion, importada por ambos servicios Python."""
    domain = ".".join(
        part.strip()[3:]
        for part in (base_dn or "").split(",")
        if part.strip().upper().startswith("DC=")
    )
    return domain.lower() if domain else "uta.edu.ec"


def _normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFD", value.strip().lower())
    stripped = "".join(
        "n" if c == "ñ" else c
        for c in normalized
        if unicodedata.category(c) != "Mn"
    )
    return unicodedata.normalize("NFC", stripped)


def _keep_allowed_alias_chars(value: str) -> str:
    return "".join(c for c in value if c.isascii() and (c.islower() or c.isdigit()))


def _tokenize(value: str) -> list[str]:
    return [
        token
        for raw in _normalize(value).split(" ")
        if raw.strip()
        for token in [_keep_allowed_alias_chars(raw)]
        if token
    ]


def _build_base_alias(given_name: str, surname: str) -> str:
    names = _tokenize(given_name)
    surnames = _tokenize(surname)

    if not names:
        raise ValueError("No se puede generar correo institucional sin nombres.")
    if not surnames:
        raise ValueError("No se puede generar correo institucional sin apellidos.")

    initials = names[0][0] + (names[1][0] if len(names) > 1 else "")
    return f"{initials}.{surnames[0]}"


def _check_availability(
    session: Session, email: str, hr_employee_id: int
) -> tuple[bool, str | None]:
    """Verifica disponibilidad en tbl_UserProvisioning, tbl_Users y AD Local.
    Retorna (True, None) si disponible; (False, motivo) si ya existe."""
    conflict = (
        session.query(UserProvisioning)
        .filter(
            UserProvisioning.email == email,
            UserProvisioning.hr_employee_id != hr_employee_id,
            UserProvisioning.provisioning_status_id != int(ProvisioningStatus.LOCAL_AD_FAILED),
        )
        .first()
    )
    if conflict is not None:
        logger.error(
            "[EMAIL-GEN] Conflicto tbl_UserProvisioning: '%s' asignado a HrEmployeeId=%s "
            "en estado '%s'",
            email, conflict.hr_employee_id, conflict.provisioning_status_name,
        )
        return False, (
            f"tbl_UserProvisioning (empleado={conflict.hr_employee_id}, "
            f"estado={conflict.provisioning_status_name})"
        )

    has_user = session.query(User).filter(User.email == email).first() is not None
    if has_user:
        logger.error("[EMAIL-GEN] Conflicto tbl_Users: '%s' ya tiene registro en auth", email)
        return False, "tbl_Users (cuenta auth ya existe)"

    ad_user = local_ad_service.find_user_by_email(email)
    if ad_user is not None:
        logger.error(
            "[EMAIL-GEN] Conflicto AD Local: '%s' ya existe en Active Directory (ObjectId=%s)",
            email, ad_user.id,
        )
        return False, f"AD Local (ObjectId={ad_user.id})"

    return True, None


def generate_available_email(
    session: Session, hr_employee_id: int, given_name: str, surname: str, base_dn: str | None
) -> str:
    alias = _build_base_alias(given_name, surname)
    domain = get_expected_domain(base_dn)
    base_email = f"{alias}@{domain}"

    logger.info(
        "[EMAIL-GEN] INICIO. HrEmployeeId=%s | GivenName='%s' | Surname='%s' | "
        "AliasBase='%s' | Dominio='%s' | CandidatoBase='%s'",
        hr_employee_id, given_name, surname, alias, domain, base_email,
    )

    for attempt in range(_MAX_ATTEMPTS):
        candidate_alias = alias if attempt == 0 else f"{alias}{attempt}"
        email = f"{candidate_alias}@{domain}"

        available, motivo = _check_availability(session, email, hr_employee_id)
        if not available:
            logger.error(
                "[EMAIL-GEN] CONFLICTO en intento %s: '%s' YA EXISTE — Motivo=%s | HrEmployeeId=%s",
                attempt, email, motivo, hr_employee_id,
            )
            continue

        logger.info(
            "[EMAIL-GEN] Email disponible encontrado en intento %s: '%s' | HrEmployeeId=%s",
            attempt, email, hr_employee_id,
        )
        return email

    logger.error(
        "[EMAIL-GEN] AGOTADOS %s intentos para HrEmployeeId=%s | AliasBase='%s@%s'",
        _MAX_ATTEMPTS, hr_employee_id, alias, domain,
    )
    raise ValueError(
        f"No se pudo generar un correo institucional disponible para el empleado {hr_employee_id}."
    )
