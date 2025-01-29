#!/bin/python3.11

import sys

from modulos.Hosts import Hosts
from modulos.ajusta_endereco import ajusta_endereco_alvo
from modulos.split_rede import split_rede
from modulos.host_ativo import host_ativo
from modulos.send_tcp_packet import envia_pacote_tcp
from modulos.ajusta_argumento_portas import ajusta_argumento_dois
from modulos.imprime import imprime_resultado_varredura as imprime
from modulos.arp_ping import arp_ping

maquinas = Hosts()

def porta_em_porta(host,ports,ifTrue): #  realiza varredura para todas portas
    if ifTrue:        
        for porta in range(int(ports[0]), int(ports[-1])+1):
            resposta_pacote=envia_pacote_tcp(host, porta)
            maquinas.set_porta_tcp(resposta_pacote)
    else:
        for porta in ports:
            resposta_pacote=envia_pacote_tcp(host, porta)
            maquinas.set_porta_tcp(resposta_pacote)

def host_em_hosts(hosts_encontrados,port): # percorre o dicionário de hosts que foram encontrados
    for host in hosts_encontrados:
        resposta_pacote=envia_pacote_tcp(host, port)
        maquinas.set_porta_tcp(resposta_pacote)

def argumento_erre(hosts_encontrados,ports,ifTrue): # caso argumento -r 
    if ifTrue:
        for porta in range(int(ports[0]), int(ports[-1])+1):
            host_em_hosts(hosts_encontrados,porta)
    else:
        for porta in ports:
            host_em_hosts(hosts_encontrados,porta)

def define_alvo(target,dash_a):
    endereco_ajustado=ajusta_endereco_alvo(target)
    rede=split_rede(endereco_ajustado)
    
    if "-" in endereco_ajustado[-1]:
        array_endereco=endereco_ajustado[-1].split("-")
        if not dash_a:
            for elemento in range(int(array_endereco[0]),int(array_endereco[-1])+1):
                verifica_enderecos=f'{rede}{elemento}'
                aux=host_ativo(verifica_enderecos)
                maquinas.adiciona_hosts_ativos(aux) if 'Ativo' in aux[verifica_enderecos]['status'] else maquinas.adiciona_hosts_inativos(aux)
        else:
                for elemento in range(int(array_endereco[0]),int(array_endereco[-1])+1):
                    aux=arp_ping(f'{rede}{elemento}')
                    for socket, recv in aux:
                        ip_mac={}
                        ip_mac[recv.psrc] = {
                            'status': 'Ativo',
                            'MAC' : f'{recv.hwsrc}' 
                            }
                        maquinas.adiciona_hosts_ativos(ip_mac)

    else:
            octetos_finais=endereco_ajustado[-1].split(",")
            if not dash_a:
                for octeto in octetos_finais:
                    verifica_enderecos=rede+str(octeto)
                    aux=host_ativo(verifica_enderecos)
                    maquinas.adiciona_hosts_ativos(aux) if 'Ativo' in aux[verifica_enderecos]['status'] else maquinas.adiciona_hosts_inativos(aux)
            else:
                for octeto in octetos_finais:
                    aux=arp_ping(f'{rede}{octeto}')
                    for socket, recv in aux:
                        ip_mac={}
                        ip_mac[recv.psrc] = {
                            'status': 'Ativo',
                            'MAC' : f'{recv.hwsrc}' 
                            }
                        maquinas.adiciona_hosts_ativos(ip_mac)

def main(argumentos):
    
    dash_v = False
    dash_o = False
    dash_a = False
    dash_f = False
    dash_r = False
    dash_h = False
    caminho = ''
    target = argumentos[1]

    if argumentos[3:]:
        for arg in argumentos[3]:
            for a in arg:
                if 'a' in a.lower():
                    dash_a=True
                elif 'h' in a.lower():
                    dash_h=True
                elif 'r' in a.lower():
                    dash_r=True
                elif 'f' in a.lower():
                    dash_f=True
                elif 'v' in a.lower():
                    dash_v=True
                elif 'o' in a.lower():
                    dash_o=True
                    caminho=argumentos[-1]
                else:
                    pass
    
    if dash_h:
        print("""
        Modo de uso: 
        -v ou --verbose : exibe detalhes
        -o ou --output : salva resultado em arquivo
        -a ou --arp : realiza varredura ARP
        -f ou --full : realiza varredura completa
        -r ou --range : varre uma faixa de portas
        -h ou --help : exibe a ajuda
        """)
        sys.exit(0)
    
    define_alvo(target,dash_a)

    if dash_f:
        host_em_hosts(maquinas.retorna_hosts_ativos('inativos'),port=80) #realiza uma outra varredura do tipo Synscan
    ports,ifTrue=ajusta_argumento_dois(argumentos[2])
    if  dash_r: #o argumento -r envia pacotes na mesma porta para hosts diferentes ( host1 -> porta1; host2 -> porta1 . . .)
        argumento_erre(maquinas.retorna_hosts_ativos('ativos'),ports,ifTrue) 
    else:
        hosts_encontrados = maquinas.retorna_hosts_ativos('ativos')  #sem o argumento -r envia pacotes em portas diferentes no mesmo hots ( host1 -> porta1; host1 -> porta2; host2 -> porta1 . . .)
        for host in hosts_encontrados:
            porta_em_porta(host,ports,ifTrue)
    imprime(maquinas.retorna_hosts_ativos('ativos'),dash_o,dash_v,dash_a,caminho)

#    print(f'Erro ao executar script, argumentos {argumentos[3:]} incompletos')

if __name__ == '__main__':
    print('''
            ####   ##   ######   ######  
            ## ##  ##   #    ##  ##      
            ##  ## ##   ######   ######  
            ##   ####   ##           ##  
            ##    ###   ##       ######           
        =========NetPyScanv2.1.0===========

       usage: python3 netpyscan.py 192.168.0.1 80 
    ''')
    argumentos=sys.argv
    main(argumentos)