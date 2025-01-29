from scapy.all import sr1, IP, ICMP

def envia_pacote_icmp(target):
    resposta_icmp=sr1(IP(dst=target)/ICMP(), timeout=2)
    return resposta_icmp