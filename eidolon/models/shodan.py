from pydantic import BaseModel


class ShodanInput(BaseModel):
    ip: str


class ShodanHostResult(BaseModel):
    ip: str
    ports: list[int] = []
    hostnames: list[str] = []
    org: str = ""
    isp: str = ""
    country: str = ""
    vulns: list[str] = []
    tags: list[str] = []
    last_update: str = ""


class ShodanOutput(BaseModel):
    ips_checked: int
    hosts: list[ShodanHostResult]
    total_open_ports: int
    total_vulns: int
    high_risk_ips: list[str]
