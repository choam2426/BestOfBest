from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

from src.db_connect import mongodb
from src.iptables_command import *
from src.update_iptables_rules_to_db import rewrite
from src.utils import convert_list_objectid_to_str

from .schemas import iptable_rule

router = APIRouter(prefix="/rules")
templates = Jinja2Templates(directory="templates")


@router.get(path="/")
async def get_rules_page(request: Request):
    iptable_rules_collection = mongodb.db["iptables_rules"]
    rules = await iptable_rules_collection.find({}).to_list(None)
    convert_list_objectid_to_str(rules)
    return templates.TemplateResponse(
        request=request, name="rules.html", context={"rules": rules}
    )


@router.get(path="/create")
async def get_rule_create_page(request: Request):
    return templates.TemplateResponse(request=request, name="rule_form.html")


@router.post(path="/create")
async def create_iptables_rules(request: Request, new_rule_data: iptable_rule):
    iptable_rules_collection = mongodb.db["iptables_rules"]
    print(append_iptables_rules(new_rule_data.dict()))
    await rewrite()
    return 1
