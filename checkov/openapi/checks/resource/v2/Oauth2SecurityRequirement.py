from typing import Dict, Any
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.common.checks.enums import BlockType
from checkov.openapi.checks.base_openapi_check import BaseOpenapiCheck


class Oauth2SecurityRequirement(BaseOpenapiCheck):
    def __init__(self) -> None:
        id = "CKV_OPENAPI_2"
        name = "Ensure that the security scheme is not of type 'oauth2', the array value must be empty"
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_entities=["*"],
                         block_type=BlockType.DOCUMENT)

    def scan_entity_conf(self, conf: Dict[str, Any], entity_type: str) -> CheckResult:
        security_values = conf.get("security")
        security_definitions = conf.get("securityDefinitions")
        irrelevant_keys = ['__startline__', '__endline__']
        non_oauth2_keys = []

        for auth_key, auth_dict in security_definitions.items():
            if auth_key in irrelevant_keys:
                continue
            auth_type = auth_dict.get("type")
            if auth_type.lower() != "oauth2":
                non_oauth2_keys.append(auth_key)

        for auth_dict in security_values:
            for key, auth_list in auth_dict.items():
                if key in irrelevant_keys:
                    continue
                if key in non_oauth2_keys and auth_list:
                    return CheckResult.FAILED

        return CheckResult.PASSED


check = Oauth2SecurityRequirement()
