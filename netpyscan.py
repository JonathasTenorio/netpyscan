#!/bin/python3.11

from scapy.all import *          #importa o scapy
import sys                         # importa sys
from datetime import datetime    # importa datetime
import os                       # importa os 

#inicializa dois dicionários vazios
hosts_encontrados = {} 
hosts_nao_encontrados= {}

# função que altera configuração do scapy para não verbosa
def configuracao_verbosa():
    conf.verb=False

# função responsável por enviar o pacote tcp Syn para ip:porta
def envia_pacote_tcp(target, port):
    response = sr1(IP(dst=target)/TCP(dport=int(port), flags="S"), timeout=1, verbose=0)
    return response

# função responsável por enviar o pacote ip/icmp
def envia_pacote_icmp(target):
    resposta_icmp=sr1(IP(dst=target)/ICMP(), timeout=2)
    return resposta_icmp

# função responsável por tratar a resposta e armazenar no dicionário
def armazena_resposta_pacote_tcp(response):

    #transforma a resposta em uma string na parte do tcp
    resposta_string=str(response[TCP])

    #divide a resposta em uma lista com dois elementos
    divide_resposta=resposta_string.split(">")

    # pega a parte da banner do serviço
    pega_flag_servico=divide_resposta[0].split(":")[-1].strip()
    
    # armazena a resposta (que seria a flag )
    pega_resposta_servico=resposta_string.split()[-1]
    
    # adiciona ao dicionário o dicionário porta onde cada host encontrado vai ter um dicionário das portas encontradas e suas respectivas situações
    hosts_encontrados[response[IP].src].setdefault('porta', {})

    # atribui valores ao dicionário porta para o ip do host correspondente
    hosts_encontrados[response[IP].src]['porta'][response[TCP].sport] = {
                                    'protocolo': 'TCP', 
                                    'flag': pega_flag_servico, 
                                    'estado': ' ',  # valor vazio apenas para inicializa-lo, a atribuição ocorre na função de analisa_resposta após verificação do código
                                    'resposta': pega_resposta_servico
                                    }

# função feita para armazenar a resposta caso a porta retorne um erro (possívelmente está filtrada por firewall ou iptables reject)
def armazena_resposta_pacote_tcperror(response):
    hosts_encontrados[response[IP].src].setdefault('porta', {})
    hosts_encontrados[response[IP].src]['porta'][response[TCPerror].dport] = {
                                    'protocolo': 'TCP', 
                                    'flag': '?', # não é possível realizar o banner grabbing dinâmicamente
                                    'estado': ' ', 
                                    }

# função para analizar a resposta do pacote e lidar com possíveis cenários
def analisa_resposta_pacote_tcp(response):

    # verifica se a resposta não é vazia e se possui a camada tcp
    if response and response.haslayer(TCP):

        # verifica se esse host está na lista dos encontrados (parte associada à funcionalidade do argumento -f )
        if response[IP].src in hosts_encontrados:

            # chama função responsável por tratar a resposta e armazenar os valores necessários 
            armazena_resposta_pacote_tcp(response)

            # verifica a flag da resposta e atribui um estado para a porta
            if (response[TCP].flags == 18):
                hosts_encontrados[response[IP].src]['porta'][response[TCP].sport]['estado'] = 'aberta'
            elif (response[TCP].flags == 20):
                hosts_encontrados[response[IP].src]['porta'][response[TCP].sport]['estado'] = 'fechada'
            else:
                hosts_encontrados[response[IP].src]['porta'][response[TCP].sport]['estado'] = 'filtrada'
        else:
            
            # armazena o host no dicionário de hosts e marca como filtrado (parte referente ao argumento -f )
            hosts_encontrados[response[IP].src] = {'status': 'Filtrado'}
    
    # caso não haja uma camada tcp, verifica se não existe uma camada de erro
    elif response and response.haslayer(TCPerror):

        # função para armazenar caso o valor seja um erro 
        armazena_resposta_pacote_tcperror(response)

        #armazena o estado da porta
        hosts_encontrados[response[IP].src]['porta'][response[TCPerror].dport]['estado'] = 'filtrada'
    else:

        # retorna código 0 para uma revisão de resposta
        return 0

# para o caso em que a porta não responde (possívelmente filtrada por firewall ou iptables drop )
def analiza_code(code,host,porta):
    if code == 0:
        hosts_encontrados[host].setdefault('porta', {})
        hosts_encontrados[host]['porta'][porta] = {
                                    'protocolo': 'TCP', 
                                    'flag': '?', # não é possível fazer banner grabbing dinâmicamente
                                    'estado': 'filtrada', 
                                    }

# função responsável por definir se o host está ativo na rede 
def host_ativo(target):

    #chama função que envia o pacote ICMP e armazena a resposta
    resposta_pacote_icmp=envia_pacote_icmp(target)

    #verifica se a resposta não retornou vazia e se possui uma camada do tipo ICMP
    if resposta_pacote_icmp and resposta_pacote_icmp.haslayer(ICMP):

        #verifica o código para de fininir se o host está ativo, filtrado ou inativo
        if resposta_pacote_icmp[ICMP].code == 0:
            hosts_encontrados[target] = {'status': 'Ativo'}
        elif (resposta_pacote_icmp[ICMP].code == 3 ):
            hosts_encontrados[target] = {'status': 'Filtrado'}
        else:
            hosts_nao_encontrados[target] = {'status': 'Inativo'}
    else:
        hosts_nao_encontrados[target] = {'status': 'Inativo'}

# função responsável por criar arquivo de log
def cria_log(caminho):

    # cria variável que armazena o valor da data/hora atual
    today=datetime.now()

    # verifica se o parâmetro caminho não é nulo, se não for, vai até o caminho
    if caminho != "":
        os.chdir(caminho)
    
    # cria variável que vai receber os valores para gerar o nome de arquivo
    log_name=f"{today.year}_{today.month}_{today.day}_{today.hour}_{today.minute}_{today.second}.log"
    
    # tenta criar/abrir o arquivo
    try:

        # abre/cria o arquivo com o nome armazenado em log_name
        arquivo = open(log_name, "w")
        return arquivo
    
    # captura o erro
    except Exception as e:
        
        #exibe o erro e retorna o valor de none
        print(f"Erro ao criar o arquivo de log: {e}")
        return None

# função que exibe o resultado 
def imprime_resultado_varredura(hosts_encontrados,array_argumentos):

    # inicia variáveis 
    msg = ""
    arquivo = None

    # verifica se o -o foi passado 
    if "-o" in array_argumentos:
        
        # chama função para criar o arquivo
        arquivo = cria_log(caminho="".join(array_argumentos).split("-o")[-1])

     # percorre o dicionário   
    for ip, info in hosts_encontrados.items():
        
        # verifica se não há nenhum inativo no meio
        if info["status"] != "Inativo":

            # armazena a saída do que será composta por ip e o estado (chave-valor)
            header = f'[+]  {ip}  [ {info["status"]} ]'

            # verifica se o header não está vazio
            if header != "":

                # verifica se a variável arquivo não é None
                if arquivo is not None:

                    # se não for, escrever o header em um arquivo de log
                    arquivo.write(header + '\n')
                
                # exibe o header se ele não for vazio
                print(f"{header}")

            # verifica se o valor de por não está vazio     
            if (info['porta'] != ""):

                # se não estiver, percorre o dicionário de portas
                for porta, info_porta in info['porta'].items():

                    # verifica se o argumento -v foi passado 
                    if "-v" in array_argumentos:

                        # armazena as respostas que estão no dicionário de portas
                        msg = f'''[-]  {porta}/{info_porta["protocolo"]}  ({info_porta["flag"]})  [ {info_porta["estado"]} ]  '''
                    
                    else:

                        # verifica se o estado não é igual fechado
                        if(info_porta["estado"] != "fechada"):

                            # armazena apenas as portas que estão estão marcadas como diferentes de fechada
                            msg = f'''[-]  {porta}/{info_porta["protocolo"]}  ({info_porta["flag"]})  [ {info_porta["estado"]} ]  '''
                    
                    # verifica se a variável não está vazia 
                    if msg != "":

                        # verifica se a variável arquivo não é None
                        if arquivo is not None:

                            # escreve no arquivo de log
                            arquivo.write(msg + '\n')

                        # exibe o valor da variável msg
                        print(msg)

                    # limpa a variável para não possuir nenhum valor indesejado     
                    msg = ""
            
            # limpa a variável para não possuir nenhum valor indesejado     
            header = ""
    
    # verifica se a variável arquivo não é None
    if arquivo is not None:
        
        # fecha o arquivo
        arquivo.close()

# função responsável por definir o endereço da rede
def split_rede(target):

    #inicia a lista rede
    rede = []
    i=0

    #pega as 3 primeiras posições que são referentes a rede
    while i < 3:
        rede.append(target[i])
        rede.append(".")
        i+=1
    
    #junta os valores criando uma única string com o endereço da rede
    rede = "".join(rede)    

    #retorna o endereço da rede
    return rede

# retorna array separado por pontos
def ajusta_endereco_alvo(verifica_enderecos):
    aux=verifica_enderecos.split(".")
    return aux

# define o alvo 
def define_alvo(target):

    #chama função que irá pegar so endereço da rede
    endereco_ajustado=ajusta_endereco_alvo(target)

    #pega sómente o endereço da rede
    rede=split_rede(endereco_ajustado)

    #verifica se existe o hífen na variável
    if "-" in endereco_ajustado:

        #faz split da ultima posição do endereço
        array_endereco=endereco_ajustado[-1].split("-")

        #inicia um loop para executar baseado na diferença entre o primeiro elemento do split até o ultimo elemento do split +1
        for elemento in range(int(array_endereco[0]),int(array_endereco[-1])+1):

            #concatena a string referente a rede com o valor do elemento formando um, endereço ip
            verifica_enderecos=rede+str(elemento)

            #chama função que verifica se o host está ativo na rede
            host_ativo(verifica_enderecos)

    else:

        # faz split da última posição por virgulas
        octetos_finais=endereco_ajustado[-1].split(",")

        #inicia um laço de repetição para cada elemento na lista resultante do split
        for octeto in octetos_finais:

            # concatena a string referente a rede com o valor do elemento, formando um endereço ip
            verifica_enderecos=rede+str(octeto)

            #chama função que verifica se o host está ativo na rede 
            host_ativo(verifica_enderecos)

#  realiza varredura para todas portas
def porta_em_porta(host,ports,ifTrue):

    # verifica se é um intervalo ou uma sequência
    if ifTrue:        

        # entra no laço e executa para todas portas no intervalo
        for porta in range(int(ports[0]), int(ports[-1])+1):

            # armazena resposta do pacote
            resposta_pacote=envia_pacote_tcp(host, porta)

            # analiza resposta e retorna um código
            code=analisa_resposta_pacote_tcp(resposta_pacote)
            
            # analiza o código da resposta
            analiza_code(code,host,porta)
    else:

        # entra no laço e executa para todas portas na lista
        for porta in ports:
            
            # armazena resposta do pacote
            resposta_pacote=envia_pacote_tcp(host, porta)

            # analiza resposta e retorna um código
            code=analisa_resposta_pacote_tcp(resposta_pacote)

            # analiza o código da resposta
            analiza_code(code,host,porta)

# percorre o dicionário de hosts que foram encontrados
def host_em_hosts(hosts_encontrados,port):

    # entra no laço percorrendo os hosts encontrados
    for host in hosts_encontrados:

        # armazena resposta do pacote
        resposta_pacote=envia_pacote_tcp(host, port)
        
        # analiza resposta e retorna um código
        code=analisa_resposta_pacote_tcp(resposta_pacote)

        # analiza o código da resposta
        analiza_code(code,host,port)

# caso argumento -r 
def argumento_erre(hosts_encontrados,ports,ifTrue):

    # verifica se ifTrue é verdadeiro
    if ifTrue:

        # entra no laço em um intervalo de valores das portas passadas       
        for porta in range(int(ports[0]), int(ports[-1])+1):
            host_em_hosts(hosts_encontrados,porta)

    else:

        # entra em um laço, percorrendo todas as portas passadas
        for porta in ports:
            host_em_hosts(hosts_encontrados,porta)

# percorre a lista de hosts encontrados
def sem_argumento_erre(hosts_encontrados,ports,ifTrue):
    for host in hosts_encontrados:
        porta_em_porta(host,ports,ifTrue)

# divite o parâmetro em uma lista
def ajusta_argumento_dois(ports):

    if "-" in ports:
        portas=ports.split("-")
        eTrue = True
    else:
        portas=ports.split(",")
        eTrue= False

    # retorna o argumento dividido em uma lista
    return portas,eTrue

# função main responsável por controlar a chamada de outras funções, passar parâmetros e analisar resultados
def main(argumentos):

    # chama função responsável por suprimir a saida do scapy
    configuracao_verbosa()

    # passa o primeiro argumento que é o ip para a variável target
    target = argumentos[1]

    # chama função responsável por devinir o alvo
    define_alvo(target)

    # verifica se o -f está presente nos argumentos
    if "-f" in argumentos:

        # caso esteja, vai realizar uma outra varredura do tipo Synscan onde, onde envia um pacote tcp/ip com a flag Syn na porta 80
        # marca os hosts não inativos que responderem como filtrado
        host_em_hosts(hosts_nao_encontrados,port=80)

    # chama função que irá ajustar os argumentos das portas
    ports,ifTrue=ajusta_argumento_dois(argumentos[2])

    # verifica se o -r está presente nos argumentos para chamar as funções
    if "-r" in argumentos:
        argumento_erre(hosts_encontrados,ports,ifTrue) # com o argumento -r envia pacotes na mesma porta para hosts diferentes ( host1 -> porta1; host2 -> porta1 . . .)
    else:
        sem_argumento_erre(hosts_encontrados,ports,ifTrue) # sem o argumento -r envia pacotes em portas diferentes no mesmo hots ( host1 -> porta1; host1 -> porta2; host2 -> porta1 . . .)


    # função responsável por exibir resultado na tela
    imprime_resultado_varredura(hosts_encontrados,array_argumentos=argumentos)

# inicia o script chamando a função main e passando os argumentos
if __name__ == '__main__':
    print('''============NeTPyscan============''')
    argumentos=sys.argv
    main(argumentos)