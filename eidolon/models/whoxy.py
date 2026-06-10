from pydantic import BaseModel


class WhoxyDomain(BaseModel):
    domain_name: str = ""
    create_date: str = ""  # "2018-04-12"
    update_date: str = ""
    expiry_date: str = ""
    registrar_name: str = ""
    registrant_name: str = ""
    registrant_email: str = ""
    registrant_company: str = ""
    registrant_address: str = ""  # may include city/state/country


class WhoxyOutput(BaseModel):
    query_email: str = ""
    query_name: str = ""
    total_results: int = 0
    domains: list[WhoxyDomain] = []

    # Aggregated signals for LLM digest
    unique_registrar_names: list[str] = []
    unique_company_names: list[str] = []  # pivot targets for OpenCorporates
    unique_addresses: list[str] = []  # physical data from WHOIS records
    active_domain_count: int = 0  # domains not yet expired
    expired_domain_count: int = 0
