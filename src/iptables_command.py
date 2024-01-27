import subprocess


def append_iptables_rules(new_rule_data):
    command = ["sudo", "iptables", "-A", "FORWARD"]
    print(new_rule_data["protocol"])
    if new_rule_data["protocol"] == "all":
        pass
    else:
        command.append("-p")
        command.append(new_rule_data["protocol"])
        if new_rule_data["s_port"]:
            command.append("--sport")
            command.append(new_rule_data["s_port"])
        if new_rule_data["d_port"]:
            command.append("--dport")
            command.append(new_rule_data["d_port"])

    if new_rule_data["s_ip"]:
        command.append("-s")
        command.append(str(new_rule_data["s_ip"]))

    if new_rule_data["d_ip"]:
        command.append("-d")
        command.append(str(new_rule_data["d_ip"]))
    command.append("-j")
    command.append(new_rule_data["target"])
    subprocess.run(command)
    return command
