import socket
import netdev
import pprint 
import struct

def long_to_ip(integer):
    return socket.inet_ntoa(struct.pack("I", integer))

def main(): 
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    #netdev.ifconf 
    fd = sock.fileno()
    print "interfaces:"
    for face in netdev.ifconf(fd):
        ip  = long_to_ip(face["addr"][1])
        print face["name"], ": ",  ip 
    print "addrs of wlan0:"
    print "addr:", long_to_ip(netdev.ifaddr(fd, "wlan0")[1])  
    print "bcast:", long_to_ip(netdev.ifbcast(fd, "wlan0")[1])
    print "dstaddr:", long_to_ip(netdev.ifdstaddr(fd, "wlan0")[1])
    print "netmask:", long_to_ip(netdev.ifnetmask(fd, "wlan0")[1])
    sock.close()

if __name__ == "__main__":
    main()
