import asyncio
from ipaddress import ip_network

from intervaltree import Interval, IntervalTree

from src.db_connect import mongodb


def is_subnet_of(top_ip, bottom_ip):
    top_net = ip_network(top_ip)
    bottom_net = ip_network(bottom_ip)
    return bottom_net.subnet_of(top_net)


def is_port_subset(top_port, bottom_port):
    if top_port is None:  # 상위 port가 all 인 경우
        return True
    elif top_port and bottom_port is None:  # 상위 port 지정인데 하위가 all 인 경우
        return False
    if ":" in top_port:
        top_start, top_end = map(int, top_port.split(":"))
    else:
        top_start, top_end = top_port
    if ":" in bottom_port:
        bottom_start, bottom_end = map(int, bottom_port.split(":"))
    else:
        bottom_start, bottom_end = bottom_port

    if top_start <= bottom_start and bottom_end <= top_end:
        return True
    else:
        return False


async def get_rules():
    iptable_rules_collection = mongodb.db["iptables_rules"]
    rules = await iptable_rules_collection.find({}).sort("number", -1).to_list(None)
    return rules


def is_match_rule(top_rule, bottom_rule):
    if top_rule["protocol"] == "all":
        pass
    elif top_rule["protocol"] == bottom_rule["protocol"]:
        pass
    else:
        return False
    if not (is_subnet_of(top_rule["s_ip"], bottom_rule["s_ip"])):
        return False
    if not (is_subnet_of(top_rule["d_ip"], bottom_rule["d_ip"])):
        return False
    if not (is_port_subset(top_rule["s_port"], bottom_rule["s_port"])):
        return False
    if not (is_port_subset(top_rule["d_port"], bottom_rule["d_port"])):
        return False
    return True


async def find_cant_match_rule():
    iptable_rules_collection = mongodb.db["iptables_rules"]
    rules = await iptable_rules_collection.find({}).sort("number", -1).to_list(None)
    for index, rule in enumerate(rules):
        for i in range(index, len(rules) - 1):
            flag = is_match_rule(rules[i + 1], rule)
            if flag:
                rule["isnt_match"] = True
                await iptable_rules_collection.update_one(
                    {"_id": rule["_id"]}, {"$set": rule}
                )
                break
        else:
            rule["isnt_match"] = False
            await iptable_rules_collection.update_one(
                {"_id": rule["_id"]}, {"$set": rule}
            )


async def find_match_rule(test_data):
    iptable_rules_collection = mongodb.db["iptables_rules"]
    rules = await iptable_rules_collection.find({}).sort("number", 1).to_list(None)
    for rule in rules:
        flag = is_match_rule(rule, test_data)
        if flag:
            return rule
    else:
        return False


if __name__ == "__main__":
    asyncio.run(find_cant_match_rule())
