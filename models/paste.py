from pydantic import BaseModel


class PasteEntry(BaseModel):
    paste_id: str = ""
    url: str = ""
    date: str = ""
    # Credential lines matching email:pass / email|pass patterns
    credential_count: int = 0
    has_plaintext_password: bool = False
    # First 3 passwords found, truncated after 4 chars for safety
    password_samples: list[str] = []


class PasteOutput(BaseModel):
    query_email: str = ""
    paste_count: int = 0
    # Pastes that contained email:password lines for this email
    credential_paste_count: int = 0
    # Pastes posted within the last 90 days
    recent_paste_count: int = 0
    pastes: list[PasteEntry] = []
    plaintext_passwords_found: int = 0
