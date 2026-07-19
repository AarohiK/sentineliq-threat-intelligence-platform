from pydantic import BaseModel


class IOCRequest(BaseModel):
    ioc: str
    type: str
