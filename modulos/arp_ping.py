from scapy.all import srp, ARP, Ether, conf
conf.verb = False

def arp_ping(target):
    aux, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=2)
    return aux