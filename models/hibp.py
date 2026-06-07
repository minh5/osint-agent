from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_pascal
from typing import Literal


class HibpInput(BaseModel):
    input_type: Literal["email", "phone"]
    value: str


class BreachRecord(BaseModel):
    model_config = ConfigDict(alias_generator=to_pascal, populate_by_name=True)

    name: str
    title: str = ""
    domain: str = ""
    breach_date: str = ""
    added_date: str = ""
    modified_date: str = ""
    pwn_count: int = 0
    description: str = ""
    logo_path: str = ""
    data_classes: list[str] = []
    is_verified: bool = False
    is_fabricated: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    is_spam_list: bool = False
    is_malware: bool = False


class HibpOutput(BaseModel):
    query_value: str
    breach_count: int
    breaches: list[BreachRecord]
    paste_count: int
