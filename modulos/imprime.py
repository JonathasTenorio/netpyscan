from .log import cria_log

def imprime_resultado_varredura(hosts_encontrados,dash_o,dash_v,dash_a,caminho):

    msg = ""
    arquivo = None

    if dash_o:
        try:
            arquivo = cria_log(caminho)
        except Exception as e:
            print(f"Não foi possível determinar o caminho do log. erro {e}")
    
    for ip, info in hosts_encontrados.items():
        if info["status"] != "Inativo":

            header = f'[+]  {ip}  [ {info["status"]} ]'

            if dash_a:
                mac = f'\n[+]  {info["MAC"]}  [ MAC ]'
            else:
                mac = ""

            if header != "":
                if arquivo is not None:
                    arquivo.write(f'{header}\n{mac}' + '\n')

                print(f"\n{header}{mac}") 

            #if (info['porta'] != ""):
            if info['porta']:
                for porta, info_porta in info['porta'].items():
                    if dash_v:
                        msg = f'''[-]  {porta}/{info_porta["protocolo"]}  ({info_porta["flag"]})  [ {info_porta["estado"]} ]  '''
                    
                    else:
                        if(info_porta["estado"] != "fechada"):
                            msg = f'''[-]  {porta}/{info_porta["protocolo"]}  ({info_porta["flag"]})  [ {info_porta["estado"]} ]  '''
                    
                    if msg != "":
                        if arquivo is not None:
                    
                            arquivo.write(msg + '\n')
                    
                        print(msg)
                    
                    msg = ""
            
            header = ""
    
    if arquivo is not None:
        arquivo.close()