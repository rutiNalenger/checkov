from __future__ import annotations

from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.arm.base_resource_check import BaseResourceCheck


class APIManagementBackendHTTPS(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure API management backend uses https"
        id = "CKV_AZURE_215"
        supported_resources = ("Microsoft.ApiManagement/service/backends",)
        categories = (CheckCategories.ENCRYPTION,)
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        properties = conf.get('properties')
        if not properties or not isinstance(properties,dict):
            return CheckResult.FAILED

        self.evaluated_keys = ["properties.url"]
        url = properties.get("url")
        if url and isinstance(url, str):
            if url.startswith("https"):
                return CheckResult.PASSED

            return CheckResult.FAILED

        return CheckResult.UNKNOWN


check = APIManagementBackendHTTPS()
