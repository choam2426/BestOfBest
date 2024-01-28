from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

from src.conntrack_parser import get_session_table

router = APIRouter(prefix="/logs")
templates = Jinja2Templates(directory="templates")


@router.get(path="/conntrack")
async def get_conntrack_log_page(request: Request):
    conntrack_log = get_session_table()

    return templates.TemplateResponse(
        request=request, name="logs.html", context={"logs": conntrack_log}
    )
