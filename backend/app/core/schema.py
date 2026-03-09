from __future__ import annotations
from typing import List, Literal, Any, Dict
from pydantic import BaseModel, Field, model_validator

YesNoUnknown = Literal["yes", "no", "unknown"]
IngressType = Literal["ALB", "APIGW", "CloudFront", "None", "Unknown"]
AuthType = Literal["none", "mTLS", "OIDC", "JWT", "APIKey", "Unknown"]
WorkloadIdentity = Literal["IRSA", "TaskRole", "StaticKeys", "Unknown"]
SecretsBackend = Literal["SecretsManager", "SSM", "K8sSecret", "EnvVar", "Vault", "Unknown"]
RotationType = Literal["auto", "manual", "none", "unknown"]
SubnetsType = Literal["private", "public", "mixed", "unknown"]

class Ingress(BaseModel):
    type: IngressType = "Unknown"
    auth: AuthType = "Unknown"
    waf: YesNoUnknown = "unknown"
    rate_limit: YesNoUnknown = "unknown"

class Egress(BaseModel):
    internet: YesNoUnknown = "unknown"
    restricted: YesNoUnknown = "unknown"
    allowed_domains: List[str] = Field(default_factory=list)

class Network(BaseModel):
    subnets: SubnetsType = "unknown"
    egress: Egress = Field(default_factory=Egress)

class Identity(BaseModel):
    workload_identity: WorkloadIdentity = "Unknown"
    iam_least_privilege: YesNoUnknown = "unknown"
    rbac: YesNoUnknown = "unknown"

class Secrets(BaseModel):
    backend: SecretsBackend = "Unknown"
    rotation: RotationType = "unknown"

class DataControls(BaseModel):
    sensitive: YesNoUnknown = "unknown"
    encryption_at_rest: YesNoUnknown = "unknown"
    encryption_in_transit: YesNoUnknown = "unknown"
    logs_may_contain_pii: YesNoUnknown = "unknown"
    redaction: YesNoUnknown = "unknown"

class SupplyChain(BaseModel):
    sbom: YesNoUnknown = "unknown"
    image_signing: YesNoUnknown = "unknown"
    container_scan: YesNoUnknown = "unknown"

class Gates(BaseModel):
    sast: YesNoUnknown = "unknown"
    sca: YesNoUnknown = "unknown"
    secrets_scan: YesNoUnknown = "unknown"
    iac_scan: YesNoUnknown = "unknown"
    policy_as_code: YesNoUnknown = "unknown"

class CiCd(BaseModel):
    gates: Gates = Field(default_factory=Gates)

class Observability(BaseModel):
    central_logging: YesNoUnknown = "unknown"
    siem: YesNoUnknown = "unknown"
    retention_days: int | Literal["unknown"] = "unknown"

class Blueprint(BaseModel):
    ingress: Ingress = Field(default_factory=Ingress)
    network: Network = Field(default_factory=Network)
    identity: Identity = Field(default_factory=Identity)
    secrets: Secrets = Field(default_factory=Secrets)
    data: DataControls = Field(default_factory=DataControls)
    supply_chain: SupplyChain = Field(default_factory=SupplyChain)
    cicd: CiCd = Field(default_factory=CiCd)
    observability: Observability = Field(default_factory=Observability)

    @model_validator(mode="after")
    def normalize_domains(self):
        self.network.egress.allowed_domains = [d.strip() for d in self.network.egress.allowed_domains if d and d.strip()]
        return self

def deep_merge(dst: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst

def apply_blueprint_patch(current: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    merged = deep_merge(dict(current), patch)
    bp = Blueprint.model_validate(merged)
    return bp.model_dump()
