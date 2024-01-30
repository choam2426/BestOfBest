import asyncio
import subprocess

from bson import ObjectId

from .db_connect import mongodb


def parse_port_number(text):
    parts = text.split()
    s_port = d_port = None
    for part in parts:
        if part.startswith("spt:"):
            s_port = part.split(":")[1]
        elif part.startswith("dpt:"):
            d_port = part.split(":")[1]
    result = {"s_port": s_port, "d_port": d_port}
    return result


def add_subnet(ip):
    if "/" in ip:
        return ip
    else:
        return ip + "/32"


def parse_iptables_forward(command_result):
    rules = []
    lines = command_result.split("\n")
    pass_count = 0
    for number, line in enumerate(lines[2:]):
        if line:
            parts = line.split()
            if parts[2] in ["ACCEPT", "DROP", "LOG"]:
                other_info = " ".join(parts[9:])
                port_data = parse_port_number(other_info)
                rule = {
                    "real_num": number + 1,
                    "number": pass_count,
                    "target": parts[2],
                    "protocol": parts[3],
                    "s_ip": add_subnet(parts[7]),
                    "d_ip": add_subnet(parts[8]),
                    "s_port": port_data.get("s_port"),
                    "d_port": port_data.get("d_port"),
                }
                fid = parts[-2].split(":")
                if parts[2] == "LOG":
                    rule["_id"] = ObjectId(fid[1])
                    rule["pkt"] = 0
                else:
                    pass_count += 1
                rules.append(rule)
    return rules


def get_iptables_rules():
    command = ["sudo", "iptables", "-nvL", "FORWARD"]
    command_result = subprocess.check_output(command, text=True)
    return command_result


async def update_iptables_rules_to_db():
    command_result = get_iptables_rules()
    rules = parse_iptables_forward(command_result)
    iptables_rules_collection = mongodb.db["iptables_rules"]
    iptables_log_rules_collection = mongodb.db["iptables_log_rules"]
    for rule in rules:
        try:
            if rule["target"] == "LOG":
                query_result = await iptables_log_rules_collection.update_one(
                    {"_id": rule["_id"]}, {"$set": rule}, upsert=True
                )
            else:
                query_result = await iptables_rules_collection.update_one(
                    {"number": rule["number"]}, {"$set": rule}, upsert=True
                )
        except Exception as e:
            print(e)


async def clear_iptable_rules_collection():
    iptable_rules_collection = mongodb.db["iptables_rules"]
    iptables_log_rules_collection = mongodb.db["iptables_log_rules"]
    query_result = await iptable_rules_collection.delete_many({})
    query_result = await iptables_log_rules_collection.delete_many({})


async def rewrite():
    await clear_iptable_rules_collection()
    await update_iptables_rules_to_db()


if __name__ == "__main__":
    mongodb.connect()
    asyncio.run(rewrite())
