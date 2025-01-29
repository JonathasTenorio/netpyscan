def split_rede(target):

    rede = []
    i=0
    while i < 3:
        rede.append(target[i])
        rede.append(".")
        i+=1
    rede = "".join(rede)    
    return rede
