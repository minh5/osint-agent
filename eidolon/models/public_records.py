from pydantic import BaseModel


class CourtCase(BaseModel):
    case_name: str
    docket_number: str
    court: str
    date_filed: str
    date_terminated: str | None = None
    nature_of_suit: str = ""
    cause: str = ""
    source_url: str = ""


class CorporateRecord(BaseModel):
    company_name: str
    role: str  # director, officer, registered-agent, etc.
    company_number: str = ""
    jurisdiction: str = ""  # us_de, us_ca, gb, etc.
    status: str = ""  # active / inactive / dissolved
    start_date: str = ""
    end_date: str = ""
    source_url: str = ""


class PublicRecordsOutput(BaseModel):
    query: str
    court_cases: list[CourtCase] = []
    corporate_records: list[CorporateRecord] = []
    court_case_count: int = 0
    corporate_record_count: int = 0
