from scapy.all import sr1, TCP, IP, conf
import logging

logging.getLogger('scapy').setLevel('CRITICAL')
conf.verb=False

def envia_pacote_tcp(target, port):
    response = sr1(IP(dst=target)/TCP(dport=int(port), flags="S"), timeout=1, verbose=0)
    return response