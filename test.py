import socket
import netdev
import pprint 
import struct

def main(): 
    sock = socket.socket(socket.AF_APPLETALK, socket.SOCK_DGRAM) 
    #netdev.ifconf 
    fd = sock.fileno()
    for face in netdev.ifconf(fd):
        ip  = socket.inet_ntoa(struct.pack("I", face["addr"][1]))
        print face["name"], ": ",  ip 
    sock.close()

if __name__ == "__main__":
    main()
