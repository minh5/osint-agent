from pydantic import BaseModel


class DehashedEntry(BaseModel):
    database_name: str = ""
    email: str = ""
    username: str = ""
    password: str = ""          # plaintext — present in some older breaches
    hashed_password: str = ""   # MD5 / SHA-1 / bcrypt etc.
    ip_address: str = ""
    phone: str = ""
    name: str = ""
    address: str = ""


class DehashedOutput(BaseModel):
    query: str
    total: int = 0                       # total hits reported by API
    entries: list[DehashedEntry] = []    # up to 50 records returned

    # Aggregated signals surfaced to the LLM
    plaintext_password_count: int = 0
    hashed_password_count: int = 0
    unique_usernames: list[str] = []     # pivot targets for Maigret
    unique_addresses: list[str] = []     # fills physical_data gap
    unique_phones: list[str] = []        # supplements phone pivot
    unique_databases: list[str] = []     # breach sources (complements HIBP)
