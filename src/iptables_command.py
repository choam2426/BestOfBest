import subprocess


def append_iptables_rule(rule_data):
    command = ["sudo", "iptables", "-A", "FORWARD"]
    print(rule_data["protocol"])
    if rule_data["protocol"] == "all":
        pass
    else:
        command.append("-p")
        command.append(rule_data["protocol"])
        if rule_data["s_port"]:
            command.append("--sport")
            command.append(rule_data["s_port"])
        if rule_data["d_port"]:
            command.append("--dport")
            command.append(rule_data["d_port"])

    if rule_data["s_ip"]:
        command.append("-s")
        command.append(str(rule_data["s_ip"]))

    if rule_data["d_ip"]:
        command.append("-d")
        command.append(str(rule_data["d_ip"]))
    command.append("-j")
    command.append(rule_data["target"])
    subprocess.run(command)
    return command


def delete_iptables_rule(rule_number):
    command = ["sudo", "iptables", "-D", "FORWARD", str(rule_number)]
    subprocess.run(command)
    return command


def update_iptables_rule(rule_number, rule_data):
    return 1
