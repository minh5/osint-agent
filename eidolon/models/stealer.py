from pydantic import BaseModel


class StealerLog(BaseModel):
    computer_name: str = ""
    operating_system: str = ""
    ip: str = ""
    date_compromised: str = ""
    malware_family: str = ""
    # How many saved credentials were on the infected machine
    credential_count: int = 0
    # How many applications were fingerprinted
    application_count: int = 0


class StealerOutput(BaseModel):
    query_email: str = ""
    found: bool = False
    stealer_count: int = 0
    logs: list[StealerLog] = []
    malware_families: list[str] = []
    # ISO date strings — earliest/latest known compromise
    earliest_compromise: str = ""
    latest_compromise: str = ""
