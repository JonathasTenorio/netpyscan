def ajusta_argumento_dois(ports):
    if "-" in ports:
        portas=ports.split("-")
        eTrue = True
    else:
        portas=ports.split(",")
        eTrue= False

    return portas,eTrue