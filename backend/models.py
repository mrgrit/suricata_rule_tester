from typing import Optional
from sqlmodel import SQLModel, Field
from datetime import datetime

class ActionLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    action: str
    detail: str
    exit_code: int = 0
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
