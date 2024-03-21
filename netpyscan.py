from scapy.all import *
import sys

def configuracao_verbosa():
    conf.verb= False

def envia_pacote_tcp(target, port):
    response = sr1(IP(dst=target)/TCP(dport=int(port), flags="S"), timeout=1, verbose=0)
    return response

def armazena_resposta_pacote(response):
    if response and response.haslayer(TCP):
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
        if (response[TCP].flags == 18):
            hosts_encontrados[response[IP].src]['porta'][response[TCP].sport]['estado'] = 'aberta'
        else:
            hosts_encontrados[response[IP].src]['porta'][response[TCP].sport]['estado'] = 'fechada'


def host_ativo(target):
    resposta_icmp=sr1(IP(dst=target)/ICMP(), timeout=2)
    if resposta_icmp and resposta_icmp.haslayer(ICMP):
        if resposta_icmp[ICMP].code == 0:
            hosts_encontrados[target] = {'status': 'Aberto'}
            return 0
        elif (resposta_icmp[ICMP].code == 3 ):
            hosts_encontrados[target] = {'status': 'Filtrado'}
            return 3
        else:
            return print(f"O host {target} não está ativo")
    else:
        return print(f"O host {target} não está ativo")
    #add verificação por TCP p/ saber se está inativo ou bloqueando protocolo ICMP 
        print(f"O host {target} está filtrado por firewall")
        hosts_encontrados[target] = {'status': 'Filtrado'}
        return 3

def imprime_resultado_varredura(hosts_encontrados,array_argumentos):
    for ip, info in hosts_encontrados.items():
        print(f'[+]  {ip}  [ {info["status"]} ]')
        if (info['porta'] != ""):
            for porta, info_porta in info['porta'].items():
                if "-v" in array_argumentos:
                    print(f'''[-]  {porta}/{info_porta["protocolo"]}  ({info_porta["flag"]})  [ {info_porta["estado"]} ]  {info_porta["resposta"]}''')
                else:
                    if(info_porta["estado"] == "aberta"):
                        print(f'''[-]  {porta}/{info_porta["protocolo"]}  ({info_porta["flag"]})  [ {info_porta["estado"]} ]  {info_porta["resposta"]}''')

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

def define_alvo(target):
    
    verifica_enderecos=target

    rede=split_rede(target)

    if "-" in verifica_enderecos:
        
        aux=verifica_enderecos.split(".")
        aux=aux[-1].split("-")
        
        for elemento in range(int(aux[0]),int(aux[-1])+1):
            verifica_enderecos=rede+str(elemento)
            host_ativo(verifica_enderecos) # ta errado, falta passos

    elif "," in verifica_enderecos:
        aux=verifica_enderecos.split(".")
        ultimo_octeto=aux[-1].split(",")
        
        for octeto in ultimo_octeto:
            
            verifica_enderecos=rede+str(octeto)
            host_ativo(verifica_enderecos)

    else:
        
        host_ativo(verifica_enderecos) 

def porta_em_porta(host,ports,ifTrue):
    if ifTrue:        
        for porta in range(int(ports[0]), int(ports[-1])+1):
            resposta_pacote=envia_pacote_tcp(host, porta)
            armazena_resposta_pacote(resposta_pacote)
    else:
        for porta in ports:
            resposta_pacote=envia_pacote_tcp(host, porta)
            armazena_resposta_pacote(resposta_pacote)
        
def host_em_hosts(hosts_encontrados,port):
    for host in hosts_encontrados:
        resposta_pacote=envia_pacote_tcp(host, port)
        armazena_resposta_pacote(resposta_pacote)

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


configuracao_verbosa()
hosts_encontrados = {}

target = sys.argv[1]

define_alvo(target)

ports,ifTrue=ajusta_argumento_dois(sys.argv[2])

if "-r" in sys.argv:
    argumento_erre(hosts_encontrados,ports,ifTrue)
else:
    sem_argumento_erre(hosts_encontrados,ports,ifTrue)

imprime_resultado_varredura(hosts_encontrados,array_argumentos=sys.argv)



# falta passar verificação de quantidade de hosts separados por - ou , ou por /bits (feito)
# falta verificação de formato do ip passado (cancelado)
# falta range de portas e verificar se é range ou valores específicos  (feito)
# falta verificação de modo verboso -v para exibir portas fechadas (feito)
# falta verificação do -f para verificar se o host esta filtrando o protocolo icmp em caso de não haver resposta 
# falta verificar quantos métodos argumentos foram passados para que todos sejam chamados da devida forma 
# falta criar uma main function para que esta organize e ordene os códigos
# falta criar função para verificar a resposta dos hosts
# falta criar função que armazene sómente as respostas e não deixar tudo junto da função que realiza o envio do pacote SYN 
# falta criar argumento -o para salvar a saída em um arquivo .log e se for -v -o salvar a saída com as portas fechadas também
