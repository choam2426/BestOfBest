from fastapi import APIRouter, HTTPException, Path, Request
from fastapi.templating import Jinja2Templates

from src.db_connect import mongodb
from src.db_control import update_number_when_delete
from src.find_match_rule import find_cant_match_rule, find_match_rule
from src.iptables_command import *
from src.update_iptables_rules_to_db import *

from .schemas import iptable_rule

router = APIRouter(prefix="/rules")
templates = Jinja2Templates(directory="templates")


@router.get(path="/")
async def get_rules_page(request: Request):
    # await rewrite()
    iptable_rules_collection = mongodb.db["iptables_rules"]
    rules = await iptable_rules_collection.find({}).to_list(None)
    return templates.TemplateResponse(
        request=request, name="rules.html", context={"rules": rules}
    )


@router.get(path="/create")
async def get_rule_create_page(request: Request):
    return templates.TemplateResponse(request=request, name="rule_form.html")


@router.post(path="/create")
async def create_iptables_rules(request: Request, new_rule_data: iptable_rule):
    iptables_rules_collection = mongodb.db["iptables_rules"]
    count = await iptables_rules_collection.count_documents({})
    insert_result = await iptables_rules_collection.insert_one({"number": count})
    objId = str(insert_result.inserted_id)
    append_iptables_rule(rule_data=new_rule_data.model_dump(), ID=objId)
    await update_iptables_rules_to_db()
    return 1


@router.get(path="/update/{rule_number}")
async def get_rule_update_page(request: Request):
    return templates.TemplateResponse(request=request, name="update_rule_form.html")


@router.put(path="/update/{rule_number}")
async def update_iptables_rules(
    request: Request, new_rule_data: iptable_rule, rule_number: int = Path()
):
    iptables_rules_collection = mongodb.db["iptables_rules"]
    iptables_log_rules_collection = mongodb.db["iptables_log_rules"]
    iptables_rule_number = await iptables_rules_collection.find_one(
        {"number": rule_number}, {"_id": 1, "real_num": 1}
    )
    new_rule_data = new_rule_data.model_dump()
    await iptables_rules_collection.update_one(
        {"number": rule_number}, {"$set": new_rule_data}
    )
    await iptables_log_rules_collection.update_one(
        {"number": rule_number}, {"$set": new_rule_data}
    )

    update_iptables_rule(
        rule_number=iptables_rule_number["real_num"],
        rule_data=new_rule_data,
        ID=str(iptables_rule_number["_id"]),
    )
    return 1


@router.delete(path="/{rule_number}")
async def delete_rule(request: Request, rule_number: int = Path()):
    iptables_rules_collection = mongodb.db["iptables_rules"]
    iptables_log_rules_collection = mongodb.db["iptables_log_rules"]
    iptables_rule_number = await iptables_rules_collection.find_one(
        {"number": rule_number}, {"_id": 0, "real_num": 1}
    )
    delete_iptables_rule(rule_number=iptables_rule_number["real_num"])
    await iptables_rules_collection.delete_one({"number": rule_number})
    await iptables_log_rules_collection.delete_one({"number": rule_number})
    await update_number_when_delete(iptables_rules_collection, rule_number)
    await update_number_when_delete(iptables_log_rules_collection, rule_number)
    return 1


@router.get(path="/unused")
async def get_unused_rule(request: Request):
    iptable_log_rules_collection = mongodb.db["iptables_log_rules"]
    rules = await iptable_log_rules_collection.find({"pkt": 0}).to_list(None)
    return templates.TemplateResponse(
        request=request, name="rules.html", context={"rules": rules}
    )


@router.get(path="/unmatched")
async def get_unmatched_rule(request: Request):
    await find_cant_match_rule()
    iptables_rules_collection = mongodb.db["iptables_rules"]
    rules = await iptables_rules_collection.find({"isnt_match": True}).to_list(None)
    return templates.TemplateResponse(
        request=request, name="rules.html", context={"rules": rules}
    )


@router.get(path="/match-test")
async def get_match_test_page(request: Request):
    return templates.TemplateResponse(request=request, name="packet_test_form.html")


@router.post(path="/match-test")
async def get_match_rule(request: Request, test_data: iptable_rule):
    test_data = test_data.model_dump()
    if test_data["protocol"] == "all":
        raise HTTPException(status_code=422, detail="dont use all")
    match_rule_data = await find_match_rule(test_data)
    return templates.TemplateResponse(
        request=request, name="rules.html", context={"rules": [match_rule_data]}
    )
