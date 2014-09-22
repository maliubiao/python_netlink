import netlink
import pdb
import cStringIO
import socket
import struct
import pprint
    

def tcp_diag(): 
    payload = netlink.new_inet_diag_req({
        "family": netlink.AF_INET,
        "protocol": netlink.IPPROTO_TCP,
        "ext": 0,
        "pad": 0,
        "states": netlink.TCPF_ALL
        }) 
    hdr = netlink.sock_diag(payload, 178431) 
    return hdr

tcp_payload_parser = netlink.parse_inet_diag_msg

def netlink_diag():
    payload = netlink.new_netlink_diag_req({
        "family": netlink.AF_NETLINK,
        "protocol": 255,
        "pad": 0,
        "ino": 0,
        "show": 0,
        "cookie": 0
        })
    hdr = netlink.sock_diag(payload, 178431) 
    return hdr

netlink_payload_parser = netlink.parse_netlink_diag_msg


def packet_diag():
    payload = netlink.new_packet_diag_req({
        "family": netlink.AF_PACKET,
        "protocol": 0,
        "pad": 0,
        "ino": 0,
        "show": netlink.PACKET_SHOW_INFO,
        "cookie0": 0,
        "cookie1": 0
        })
    hdr = netlink.sock_diag(payload, 178431)
    return hdr

packet_payload_parser = netlink.parse_packet_diag_msg

def unix_diag():
    payload = netlink.new_unix_diag_req({
        "family": netlink.AF_UNIX,
        "protocol": 0,
        "pad": 0,
        "states": 255,
        "ino": 0,
        "show": netlink.UNIX_DIAG_NAME|netlink.UNIX_DIAG_PEER,
        "cookie0": 0,
        "cookie1": 0
        })
    hdr = netlink.sock_diag(payload, 178431)
    return hdr

unix_payload_parser = netlink.parse_unix_diag_msg

def get_sock_diag(hdr, payload_parser):
    con = netlink.new_sock_diag() 
    con.send(hdr) 
    msgs = []
    goout = False
    while True: 
        d = con.recv(65533) 
        b = cStringIO.StringIO(d) 
        while True: 
            if b.tell() >= len(d):
                break
            msg = netlink.parse_nlmsg(b) 
            if msg["type"] == netlink.DONE: 
                goout = True
                break
            elif msg["type"] == netlink.ERROR:
                raise ValueError(msg)
            mlen = b.tell() - 16 + msg["len"]
            payload = payload_parser(b)
            attrs = netlink.parse_attrs(b, mlen) 
            msgs.append({
                "msg": msg,
                "payload": payload,
                "attrs": attrs
                }) 
        if goout:
            break
    b.close()
    return msgs 

state_table = (
        "EMPTY SLOT",
        "ESTABLISHED",
        "SENT",
        "RECV",
        "WAIT1",
        "WAIT2",
        "WAIT",
        "CLOSE",
        "CLOSE_WAIT",
        "LAST_ACK",
        "LISTEN",
        "CLOSING"
        ) 

def print_tcp(msgs): 
    of = "{:<30}{:<30}{:<20}{:<20}" 
    print of.format("SRC", "DST", "R/W QUEUE", "STATE") 
    for msg in msgs:
        p = msg["payload"] 
        srcip = socket.inet_ntoa(struct.pack(">I", p["src"][0]))
        dstip = socket.inet_ntoa(struct.pack(">I", p["dst"][0]))
        srcp = p["sport"]
        dstp = p["dport"] 
        state = state_table[p["state"]] 
        print of.format("%s:%s" % (srcip, srcp),
                "%s:%s" % (dstip, dstp),
                "%s/%s" % (p["rqueue"], p["wqueue"]),
                state)


def main():
    msgs = get_sock_diag(tcp_diag(), tcp_payload_parser)
    print_tcp(msgs)

if __name__ == "__main__":
    main()

