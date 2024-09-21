import re
import subprocess


def conntrack_parse(result):
    logs = []
    for line in result.splitlines():
        # 정규 표현식을 사용하여 필요한 정보 추출
        match = re.search(
            r"(\w+)\s+.*src=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)", line
        )
        if match:
            conn_info = {
                "protocol": match.group(1),
                "src": match.group(2),
                "dst": match.group(3),
                "sport": match.group(4),
                "dport": match.group(5),
                # "detail": line,
            }
            logs.append(conn_info)
            continue
        match = re.search(r"(\w+)\s+.*src=(\S+)\s+dst=(\S+)\s", line)
        if match:
            conn_info = {
                "protocol": match.group(1),
                "src": match.group(2),
                "dst": match.group(3),
                "sport": None,
                "dport": None,
                # "detail": line,
            }
            logs.append(conn_info)

    return logs


def get_conntrack():
    command = ["sudo", "conntrack", "-L"]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout


def get_session_table():
    conntrack_log = get_conntrack()
    return conntrack_parse(conntrack_log)
