import argparse
import socket
from sys import flags
from scapy.all import IP, TCP, Ether

MAX_HOPS = 30
DST_PORT = 80
TARGET = ""
HOST = "172.17.149.28"

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

    ip = IP(dst=TARGET)
    tcp = TCP(sport=recv_sock.getsockname()[1], dport=DST_PORT, flags="S")
    packet = ip/tcp
    packet.show()

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(bytes(packet), (TARGET, DST_PORT))
    
    msgFromServer = recv_sock.recv(65565)
    recieved = Ether(msgFromServer)
    recieved.show()