from datetime import datetime

from repositoryuta.core.schema_base import ApiModel


class AppParamRead(ApiModel):
    nemonic: str
    value: str
    data_type: str
    category: str
    description: str | None
    is_encrypted: bool
    last_modified: datetime
    modified_by: str | None


class AppParamCreate(ApiModel):
    nemonic: str
    value: str
    data_type: str | None = None
    category: str | None = None
    description: str | None = None
    is_encrypted: bool | None = None
    modified_by: str | None = None


class AppParamUpdate(ApiModel):
    value: str | None = None
    data_type: str | None = None
    category: str | None = None
    description: str | None = None
    is_encrypted: bool | None = None
    modified_by: str | None = None
