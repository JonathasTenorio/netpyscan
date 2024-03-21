from scapy.all import *
import sys

hosts_encontrados = {}
hosts_nao_encontrados= {}

def configuracao_verbosa():
    conf.verb= False

def envia_pacote_tcp(target, port):
    response = sr1(IP(dst=target)/TCP(dport=int(port), flags="S"), timeout=1, verbose=0)
    return response

def envia_pacote_icmp(target):
    resposta_icmp=sr1(IP(dst=target)/ICMP(), timeout=2)
    return resposta_icmp

def armazena_resposta_pacote_tcp(response):
    resposta_string=str(response[TCP])
    divide_resposta=resposta_string.split(">")
    pega_flag_servico=divide_resposta[0].split(":")[-1].strip()
    pega_resposta_servico=resposta_string.split()[-1]
    hosts_encontrados[response[IP].src].setdefault('porta', {})
    hosts_encontrados[response[IP].src]['porta'][response[TCP].sport] = {
                                    'protocolo': 'TCP', 
                                    'flag': pega_flag_servico, 
                                    'estado': ' ', 
                                    'resposta': pega_resposta_servico
                                    }

def armazena_resposta_pacote_tcperror(response):
    hosts_encontrados[response[IP].src].setdefault('porta', {})
    hosts_encontrados[response[IP].src]['porta'][response[TCPerror].dport] = {
                                    'protocolo': 'TCP', 
                                    'flag': '?',
                                    'estado': ' ', 
                                    }

def analisa_resposta_pacote_tcp(response):
    if response and response.haslayer(TCP):
        if response[IP].src in hosts_encontrados:
            armazena_resposta_pacote_tcp(response)
            if (response[TCP].flags == 18):
                hosts_encontrados[response[IP].src]['porta'][response[TCP].sport]['estado'] = 'aberta'
            elif (response[TCP].flags == 20):
                hosts_encontrados[response[IP].src]['porta'][response[TCP].sport]['estado'] = 'fechada'
            else:
                hosts_encontrados[response[IP].src]['porta'][response[TCP].sport]['estado'] = 'filtrada'
        else:
            hosts_encontrados[response[IP].src] = {'status': 'Filtrado'}
    elif response and response.haslayer(TCPerror):
        armazena_resposta_pacote_tcperror(response)
        hosts_encontrados[response[IP].src]['porta'][response[TCPerror].dport]['estado'] = 'filtrada'
    else:
        return 0

def analiza_code(code,host,porta):
    if code == 0:
        hosts_encontrados[host].setdefault('porta', {})
        hosts_encontrados[host]['porta'][porta] = {
                                    'protocolo': 'TCP', 
                                    'flag': '?',
                                    'estado': 'filtrada', 
                                    }

def host_ativo(target):
    resposta_pacote_icmp=envia_pacote_icmp(target)
    if resposta_pacote_icmp and resposta_pacote_icmp.haslayer(ICMP):
        if resposta_pacote_icmp[ICMP].code == 0:
            hosts_encontrados[target] = {'status': 'Ativo'}
        elif (resposta_pacote_icmp[ICMP].code == 3 ):
            hosts_encontrados[target] = {'status': 'Filtrado'}
        else:
            hosts_nao_encontrados[target] = {'status': 'Inativo'}
    else:
        hosts_nao_encontrados[target] = {'status': 'Inativo'}

def imprime_resultado_varredura(hosts_encontrados,array_argumentos):
    for ip, info in hosts_encontrados.items():
        if info["status"] != "Inativo":
            print(f'[+]  {ip}  [ {info["status"]} ]')
            if (info['porta'] != ""):
                for porta, info_porta in info['porta'].items():
                    if "-v" in array_argumentos:
                        print(f'''[-]  {porta}/{info_porta["protocolo"]}  ({info_porta["flag"]})  [ {info_porta["estado"]} ]  ''')
                    else:
                        if(info_porta["estado"] != "fechada"):
                            print(f'''[-]  {porta}/{info_porta["protocolo"]}  ({info_porta["flag"]})  [ {info_porta["estado"]} ]  ''')

def split_rede(target):
    aux=target.split(".")
    rede = []
    i=0
    while i < 3:
        rede.append(aux[i])
        rede.append(".")
        i+=1
    rede = "".join(rede)    
    return rede

def ajusta_endereco_alvo(verifica_enderecos):
    aux=verifica_enderecos.split(".")
    return aux

def define_alvo(target):
    rede=split_rede(target)
    endereco_ajustado=ajusta_endereco_alvo(target)
    if "-" in target:
        array_endereco=endereco_ajustado[-1].split("-")
        for elemento in range(int(array_endereco[0]),int(array_endereco[-1])+1):
            verifica_enderecos=rede+str(elemento)
            host_ativo(verifica_enderecos)
    else:
        octetos_finais=endereco_ajustado[-1].split(",")
        for octeto in octetos_finais:
            verifica_enderecos=rede+str(octeto)
            host_ativo(verifica_enderecos)

def porta_em_porta(host,ports,ifTrue):
    if ifTrue:        
        for porta in range(int(ports[0]), int(ports[-1])+1):
            resposta_pacote=envia_pacote_tcp(host, porta)
            code=analisa_resposta_pacote_tcp(resposta_pacote)
            analiza_code(code,host,porta)
    else:
        for porta in ports:
            resposta_pacote=envia_pacote_tcp(host, porta)
            code=analisa_resposta_pacote_tcp(resposta_pacote)
            analiza_code(code,host,porta)

def host_em_hosts(hosts_encontrados,port):
    for host in hosts_encontrados:
        resposta_pacote=envia_pacote_tcp(host, port)
        code=analisa_resposta_pacote_tcp(resposta_pacote)
        analiza_code(code,host,port)

def argumento_erre(hosts_encontrados,ports,ifTrue):
    if ifTrue:        
        for porta in range(int(ports[0]), int(ports[-1])+1):
            host_em_hosts(hosts_encontrados,porta)

    else:
        for porta in ports:
            host_em_hosts(hosts_encontrados,porta)

def sem_argumento_erre(hosts_encontrados,ports,ifTrue):
    for host in hosts_encontrados:
        porta_em_porta(host,ports,ifTrue)

def ajusta_argumento_dois(ports):
    if "-" in ports:
        portas=ports.split("-")
        eTrue = True
    else:
        portas=ports.split(",")
        eTrue= False

    return portas,eTrue

def main(argumentos):

    configuracao_verbosa()

    target = argumentos[1]

    define_alvo(target)

    if "-f" in argumentos:
        host_em_hosts(hosts_nao_encontrados,port=80)

    ports,ifTrue=ajusta_argumento_dois(argumentos[2])

    if "-r" in argumentos:
        argumento_erre(hosts_encontrados,ports,ifTrue)
    else:
        sem_argumento_erre(hosts_encontrados,ports,ifTrue)

    imprime_resultado_varredura(hosts_encontrados,array_argumentos=argumentos)

if __name__ == '__main__':
    argumentos=sys.argv
    main(argumentos)