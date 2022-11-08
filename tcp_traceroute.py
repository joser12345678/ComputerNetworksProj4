import argparse
import socket
from sys import flags
from scapy.all import IP, TCP, Ether, raw
import time

MAX_HOPS = 30
DST_PORT = 80
TARGET = ""



# sends a single probe with specified ttl
def sendProbe(my_ttl, my_id):
    ip = IP(dst=TARGET, ttl=my_ttl, id = my_id)
    tcp = TCP(sport=recv_sock.getsockname()[1], dport=DST_PORT, flags="S")
    packet = ip/tcp
    print(IP(raw(packet))[IP].id)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(bytes(packet), (TARGET, DST_PORT))

# recieves a probe, will listen until timeout
def recieveProbe():
    recv_sock.settimeout(1)
    try:
        msgFromServer = recv_sock.recv(65565)
        recieved = Ether(msgFromServer)
        recieved.show()
    except Exception as e:
        print("No reply, timeout")

def setParams():
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', metavar='MAX_HOPS', type=int, help="Max hops to probe (default = 30)")
    parser.add_argument('-p', metavar='DST_PORT', type=str, help="TCP destination port (default = 80)")
    parser.add_argument('-t', metavar='TARGET', type=str,
                        help="Target domain or IP")


    # parse arguments and put into args
    args = parser.parse_args()
    global TARGET, MAX_HOPS, DST_PORT

    # a target must always be specified
    if not args.t:
        print("No target specified. Terminating.")
        exit()
    else:
        TARGET = args.t
    
    # set optional arguments
    if args.m:
        MAX_HOPS = args.m
    if args.p:
        DST_PORT = args.p


if __name__ == '__main__':
    setParams()

    TARGET = socket.gethostbyname(TARGET)
    
    ETH_P_IP = 0x0800
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP)) 
    recv_sock.bind(('ens3', 0))

    #sendProbe(1, 1)
    #sendProbe(1, 2)
    sendProbe(1, 3)
    recieveProbe()

    #print(time.time_ns())
    