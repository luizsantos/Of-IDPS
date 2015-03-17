from time import sleep

INTERVALO = 1

def pega_campo(dados, limitador_i, limitador_f):
        i = 0
        while dados[i] != limitador_i:
            i += 1
            
        inicio = i+1
        while dados[i] != limitador_f:
            i += 1
        return inicio, i

def processa_linha_log(linha):
    lista = []
    
    linha = linha.rstrip()
    lista = linha.split("[**]")
    time = lista[0].strip()
    msg = lista[1].strip()
    dados = lista[2]
    
    # pega classificacao
    i,f = pega_campo(dados,":","]")
    classificacao = dados[i:f].strip()

    # pega prioridade
    dados = dados[f:]
    i,f = pega_campo(dados,":","]")
    prioridade = dados[i:f].strip()

    # pega protocolo
    dados = dados[f:]
    i,f = pega_campo(dados,"{","}")
    proto = dados[i:f].strip()

    # pega ip e porta origem
    dados = dados[f+1:]
    l = dados.split("->")
    l_src = l[0].split(":")
    l_dst = l[1].split(":")

    src = l_src[0].strip()
    dst = l_dst[0].strip()
    if len(l_src) == 2:
        portsrc = l_src[1].strip()
        portdst = l_dst[1].strip()
    else:
        portsrc = "0"
        portdst = "0"

    alert = "%s,%s,%s,%s,%s,%s,%s,%s" % (time,prioridade,msg,src,dst,proto,portsrc,portdst)
    with open("formatted_log.csv",'a') as log:
        log.write(alert+"\n")
    print(alert)

def leitura_log(arquivo):
    arquivo = open(arquivo, 'r')
    while True:
        posicao = arquivo.tell()
        linha = arquivo.readline()
        if not linha:
            sleep(INTERVALO)
            arquivo.seek(posicao)
        else:
            processa_linha_log(linha)

leitura_log("/mnt/armazem/openflow/tmp/alertas/alert.fast")
