from typing import Literal

from pydantic import BaseModel


class PhoneInput(BaseModel):
    phone: str  # raw or E.164 format


class PhoneCarrierInfo(BaseModel):
    name: str
    type: Literal["mobile", "landline", "voip", "prepaid", "unknown"] = "unknown"


class PhoneLookupOutput(BaseModel):
    phone: str
    valid: bool
    carrier: PhoneCarrierInfo | None = None
    line_type: str = "unknown"  # mobile / landline / voip / prepaid
    country_code: str = ""
    country_name: str = ""
    location: str = ""   # city or region where the number was registered
    geocode: str = ""    # human-readable geographic description (from libphonenumber)
    timezone: list[str] = []  # IANA timezone(s) for the number's area
    international_format: str = ""
    local_format: str = ""
    # True when line_type is voip — throwaway/anonymous number risk flag
    is_voip: bool = False
