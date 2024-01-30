import asyncio
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta

from .db_connect import mongodb
from .db_control import update_pkt


def get_log():
    command = "cat /var/log/syslog | grep FID"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    return result.stdout


def parse_log(logs):
    # 정규표현식을 사용하여 필요한 정보 추출
    patterns = {
        "mac": r"MAC=(\S+):",
        "src_ip": r"SRC=(\S+)",
        "dst_ip": r"DST=(\S+)",
        "src_port": r"SPT=(\d+)",
        "dst_port": r"DPT=(\d+)",
        "protocol": r"PROTO=(\S+)",
        "fid": r"FID:(\S+)",
        "time": r"(\w+ \d+ \d+:\d+:\d+)",
    }
    parsed_log = []
    for line in logs:
        parsed_data = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, line)
            if match:
                if key == "mac":
                    parsed_data["s_mac"] = match.group(1)[0:17]
                    parsed_data["d_mac"] = match.group(1)[17:34]
                else:
                    parsed_data[key] = match.group(1)
        parsed_log.append(parsed_data)

    return parsed_log


def read_recent_logs(logs, seconds=5):
    current_time = datetime.now()

    recent_logs = []

    for line in logs.splitlines():
        timestamp_match = re.search(r"(\w+ \d+ \d+:\d+:\d+)", line)
        if timestamp_match:
            log_timestamp_str = timestamp_match.group(1)
            log_timestamp_str = f"{datetime.now().year} {log_timestamp_str}"
            log_timestamp = datetime.strptime(log_timestamp_str, "%Y %b %d %H:%M:%S")
            if (current_time - log_timestamp) <= timedelta(seconds=seconds):
                recent_logs.append(line)

    return recent_logs


def get_parsed_log():
    logs = get_log()
    logs = read_recent_logs(logs)
    if logs:
        return parse_log(logs)
    else:
        return 0


async def update_log_db():
    mongodb.connect()
    while True:
        logs = get_parsed_log()
        if logs:
            logs_collection = mongodb.db["logs"]
            iptables_log_rules_collection = mongodb.db["iptables_log_rules"]
            for log in logs:
                await logs_collection.insert_one(log)
                await update_pkt(iptables_log_rules_collection, log["fid"])
        await asyncio.sleep(5)


def log_sync():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(update_log_db())
    loop.close()

    thread = threading.Thread(target=start_async_loop)
    thread.start()
