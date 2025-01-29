import os
import datetime

def cria_log(caminho):

    today=datetime.date.today()

    if caminho == "":
        os.getcwd(caminho)
        log_name=f"{today.year}_{today.month}_{today.day}.log"
    else:
        os.chdir(caminho)
        log_name=f"{today.year}_{today.month}_{today.day}.log"
    
    try:
        arquivo = open(log_name, "w")
        return arquivo
    except Exception as e:
        print(f"Erro ao criar o arquivo de log: {e}")
        return None