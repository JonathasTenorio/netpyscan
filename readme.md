# NeTPyscan
## Projeto script em python para varrer redes internas 


### O script recebe como argumento o ip da rede alvo e as portas de serviço que serão verificadas. 
script desenvolvido para fins didáticos. 

---

Requisitos:

 * python3
 * scapy
     ###### para windows
    * Npcap
---
### Sinopse


O NeTPyscan é uma ferramenta de código aberto para varredura de redes internas que utiliza em seu core a biblioteca scapy. Esta ferramenta foi desenvolvida para escanear redes internas em busca de hosts e serviços ativos, utilizando o protocolos ip, icmp e tcp para detectar as portas e serviços.

---
### Modo de uso:

#### Primeiro uso:

Ao utilizar o netpyscan é necessário passar os argumentos que deseja como ip(s) e porta(s) de destino, é necessário ser utilizado com permissão de super usuário (sudo).


1) Passando ip como argumento:

   * `netpyscan 10.0.0.100 80`

    Realiza a varredura  do host atual na porta 80.

---

2) Passando sequência ip's como argumento:

   * `netpyscan 10.0.0.100,102,115,200 80`

    Realiza a varredura  dos hosts na ordem indicada e para cada host, a varredura da porta, que neste caso é a 80.

---

3) Passando intervalo ip's como argumento:

   * `netpyscan 10.0.0.100-200 80`

   Realiza a varredura  no intervalo do último octeto até o indicado, apenas intervalo de ordem crescente se não resultará em erro.

---

4) Passando portas como argumento:

   * `netpyscan 10.0.0.100 22,23,24,25,26`

    Realiza a varredura da sequência de portas.

---
5) Passando intervalo de portas como argumento:

    * `netpyscan 10.0.0.100 22-26`

        Realiza a varredura do intervalo das portas.

---
6) Opção detalhada:

    * `netpyscan 10.0.0.100 22 -v`

        Durante a varredura das portas exibe também as portas fechadas.

---
7) Opção de filtro:

    * `netpyscan 10.0.0.100 22 -f`

        Realiza uma segunda varredura nos hosts que não responderam ao ping do ICMP, envinado uma requisição do tipo tcp/ip com flag SYN.
---

8) Opção reversa:

    * `netpyscan 10.0.0.100-120 22-25 -r`

        Este argumento faz com que no lugar de varrer todas as portas de um host alvo antes de ir para o próximo, ele ira enviar o pacote para a mesma porta em todos os hosts encontrados antes de seguir para a próxima porta.
---

9) Salvando saída em um arquivo:

    * `netpyscan 10.0.0.100-120 22-25 -o /caminho/do/arquivo/de/log`

        Cria um arquivo de log no caminho específicado com o nome da data e tendo como contéudo a saída do que foi exibido na tela.
            Caso não seja passado um caminho, cria o arquivo no mesmo diretório do script.
---

10) Múltiplas opções:

    * `netpyscan 10.0.0.100-120 22-25 -r -f -v -o /home/usuario/`

        O netpyscan aceita múltiplos argumentos, executando todos eles.
---


### Documentação

Links para documenttação que irão auxiliar na compreensão do script e na instalação das depêndencias necessárias.

* [Scapy](https://scapy.net/)

* [python3.sys](https://docs.python.org/3/library/sys.html#module-sys)

* [python3.os](https://docs.python.org/3/library/os.html#module-os)

* [python3.datetime](https://docs.python.org/3/library/datetime.html#module-datetime)

* [Técnicas de Escaneamento de Portas](https://nmap.org/man/pt_BR/man-port-scanning-techniques.html)
---