from pydantic import BaseModel
from typing import Literal


class HibpInput(BaseModel):
    input_type: Literal["email", "phone"]
    value: str


class BreachRecord(BaseModel):
    name: str
    title: str
    domain: str
    breach_date: str
    added_date: str
    modified_date: str
    pwn_count: int
    description: str
    logo_path: str
    data_classes: list[str]
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    is_retired: bool
    is_spam_list: bool
    is_malware: bool


class HibpOutput(BaseModel):
    query_value: str
    breach_count: int
    breaches: list[BreachRecord]
    paste_count: int
