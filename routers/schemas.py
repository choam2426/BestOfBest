from typing import Optional

from pydantic import BaseModel, validator
from pydantic.networks import IPv4Network


class iptable_rule(BaseModel):
    target: str
    protocol: str
    s_ip: IPv4Network
    d_ip: IPv4Network
    s_port: Optional[str] = None
    d_port: Optional[str] = None

    @validator("s_ip", "d_ip")
    def validate_and_convert_ip(cls, v):
        return str(v)
