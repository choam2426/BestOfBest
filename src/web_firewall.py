import subprocess

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw


def add_nfqueue():
    command = "sudo iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0"
    subprocess.run(command, shell=True)


def detect_sql_injection():
    # 시그니처 탐지
    pass


def detect_xss():
    # 시그니처 탐지
    pass


def prevention_xss():
    # "<" ">"이스케이프 문자로 치환
    pass


def nfqueue_filter():
    sqli_attack_flag = detect_sql_injection()
    if sqli_attack_flag:
        pass
    xss_attack_flag = detect_xss()
    if xss_attack_flag:
        pass
        prevention_xss()


def run_nfqueue_filter():
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, nfqueue_filter)
