from scapy.all import TCP, IP, TCPerror

class Hosts:
    def __init__(self):
        self.hosts_ativos = {}
        self.hosts_inativos = {}
    
    def adiciona_hosts_ativos(self, hosts):
        if hosts:
            try:
                for host, status in hosts.items():
                    self.hosts_ativos[host] = status
            except Exception as e:
                 print(f"Erro ao adicionar host {host}: \n {e}")

    def adiciona_hosts_inativos(self, hosts):
        if hosts:
            try:
                for host, status in hosts.items():
                    self.hosts_inativos[host] = status
            except Exception as e:
                 print(f"Erro ao adicionar hosts inativos {host}: \n {e}")
    
    def retorna_hosts_ativos(self, estado):
        try:
            return self.hosts_ativos if estado == 'ativos' else self.hosts_inativos
        except Exception as e:
             print(f"Erro ao retornar o hosts {estado} \n {e}")


    def _determina_estado_porta(self, resposta):
        if resposta[TCP].flags == 'SA':
             return 'aberta'
        elif resposta[TCP].flags == 'RA':
             return 'fechada'
        else:
             return 'filtrada'
    
    def set_porta_tcp(self, resposta):
        if resposta and resposta.haslayer(TCP):

            ip_src = resposta[IP].src
        
            if ip_src in self.hosts_ativos:
                
                    porta = resposta[TCP].sport
                    resposta_string=str(resposta[TCP])
                    divide_resposta=resposta_string.split(">")
                    pega_flag_servico=divide_resposta[0].split(":")[-1].strip()                
                    pega_resposta_servico=resposta_string.split()[-1]
                    self.hosts_ativos[ip_src].setdefault('porta', {})
                    self.hosts_ativos[ip_src]['porta'][porta] = {
                                                    'protocolo': 'TCP', 
                                                    'flag': pega_flag_servico, 
                                                    'estado': f'{self._determina_estado_porta(resposta)}', 
                                                    'resposta': pega_resposta_servico
                                                    }
            else:    
                    self.hosts_ativos[ip_src] = {'status': 'Filtrado'}
            
        elif resposta and resposta.haslayer(TCPerror):
            self._set_resposta_tcperror(resposta)
        else:
            return None
            
    def _set_resposta_tcperror(self, resposta):
        ip_src = resposta[IP].src
        self.hosts_ativos[ip_src].setdefault('porta', {})
        self.hosts_ativos[ip_src]['porta'][resposta[TCPerror].dport] = {
                                    'protocolo': 'TCP', 
                                    'flag': '?',
                                    'estado': 'filtrada', 
                                    }