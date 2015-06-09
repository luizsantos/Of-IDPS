import sys
sys.path.append('/home/mininet/mininet/custom/testesOF/')

def teste1(net):
    info('teste1 - ping (4msgs/cada):\nhost1->host6\nhost2->host1\nhost5->host2\nhost6->host5')
    #hosts que serao utilizados
    host1 = net.getNodeByName('h1')
    host2 = net.getNodeByName('h2')
    host5 = net.getNodeByName('h5')
    host6 = net.getNodeByName('h6')
    
    #cria diretorio que recebera arquivos do tcpdump (pacotes de redes)
    host1.cmd('mkdir /var/log/tcpdump/'+date)
    #captura pacotes em todos os hosts - exceto switches e IDS(host3)
    tcpdumpAll(net)
    
    #Configura comandos a serem executados simultaneamente via threads
    th1=thCmd(host1,'ping 192.168.0.6 -c 4')
    th2=thCmd(host2,'ping 10.0.0.1 -c 4')
    th5=thCmd(host5,'ping 10.0.0.2 -c 4')
    th6=thCmd(host6,'ping 192.168.0.5 -c 4')
    
    #Dispara comandos via threads
    th1.start()
    th2.start()
    th5.start()
    th6.start()

    #Espera todos os comandos disparados via thread terminarem!
    th1.join()
    th2.join()
    th5.join()
    th6.join()

    #Finaliza tcpdumps
    tcpdumpKill(net)