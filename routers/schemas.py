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

    @validator("s_port", "d_port")
    def parse_str_to_int(cls, v):
        if v is None or v == "":
            return None
        try:
            int_v = int(v)
        except ValueError:
            raise ValueError("port는 0과 65535 사이의 값이어야 합니다")
        if not 0 <= int_v <= 65535:
            raise ValueError("port는 0과 65535 사이의 값이어야 합니다")
        return v
