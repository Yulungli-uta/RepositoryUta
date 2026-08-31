from repositoryuta.core.schema_base import ApiModel

# Espejo de LicenseDtos.cs.


class SubscribedSkuRead(ApiModel):
    sku_id: str
    sku_part_number: str
    capability_status: str | None
    prepaid_units_enabled: int | None
    consumed_units: int | None
    available_units: int | None


class UserLicenseRead(ApiModel):
    sku_id: str
    sku_part_number: str | None


class LicenseAssignRequest(ApiModel):
    upn: str
    sku_part_number: str
    country_code: str = "EC"


class LicenseAssignEmployeeRequest(ApiModel):
    upn: str
    country_code: str = "EC"


class LicenseOperationResultRead(ApiModel):
    success: bool
    upn: str
    sku_part_number: str | None
    sku_id: str | None
    message: str | None
