from scapy.all import ICMP
from modulos.icmp_packet import envia_pacote_icmp as icmp

def host_ativo(target):

    hosts_encontrados = {}
    hosts_nao_encontrados = {}
    resposta_pacote_icmp=icmp(target)

    if resposta_pacote_icmp and resposta_pacote_icmp.haslayer(ICMP):
        if resposta_pacote_icmp[ICMP].code == 0:
             hosts_encontrados[target] = {
                'status': 'Ativo',
                'MAC' : ''
                                          }
             return hosts_encontrados
        elif (resposta_pacote_icmp[ICMP].code == 3 ):
            hosts_encontrados[target] = {
                'status': 'Filtrado',
                'MAC' : '' }
            return hosts_encontrados
        else:
            hosts_nao_encontrados[target] = {
                'status': 'Inativo',
                'MAC' : '' }
            return hosts_nao_encontrados
    else:
        hosts_nao_encontrados[target] = {
            'status': 'Inativo',
                'MAC' : '' }
        return hosts_nao_encontrados