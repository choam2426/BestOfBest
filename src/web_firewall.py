import re
import subprocess

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

from .pattern import sql_injection_patterns, xss_keyword_patterns


def add_nfqueue():
    command = "sudo iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 1"
    subprocess.run(command, shell=True)


def detect_sql_injection(http_payload):
    for pattern in sql_injection_patterns:
        if re.search(pattern, http_payload):
            print("sqli detected!")


def detect_xss(http_payload):
    for pattern in xss_keyword_patterns:
        if re.search(pattern, http_payload):
            print("xss detected!")
            return 1
    else:
        return 0


def prevention_xss(http_payload):
    # "<" ">"이스케이프 문자로 치환
    targets = {"<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;"}
    for keyword in targets.keys():
        new_payload = http_payload.replace(keyword, targets[keyword])
    print(new_payload)
    return new_payload


def nfqueue_filter(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(TCP):
        tcp_layer = scapy_packet[TCP]
        if hasattr(tcp_layer, "load"):
            http_payload = scapy_packet[TCP].load.decode()
            detect_sql_injection(http_payload)
            xss_flag = detect_xss(http_payload)
            if xss_flag:
                new_payload = prevention_xss(http_payload)
                scapy_packet[Raw].load = new_payload
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[TCP].chksum
                packet.set_payload(bytes(scapy_packet))
        packet.accept()


class nfqueueFilter:
    def __init__(self) -> None:
        self.nfqueue = NetfilterQueue()

    def run_nfqueue_filter(self):
        add_nfqueue()
        self.nfqueue.bind(1, nfqueue_filter)
        print("run")
        self.nfqueue.run()

    def close_nfqueue_filter(self):
        self.nfqueue.unbind()
        self.nfqueue.break_loop()


filter = nfqueueFilter()
