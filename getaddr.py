import netlink
import cStringIO
import pdb
import pprint

def getaddr_inet():
    con = netlink.new_route()
    payload = netlink.route_getaddr(netlink.AF_INET, 0x12345) 
    con.send(payload)
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
            payload = netlink.parse_ifaddr(b) 
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

pprint.pprint(getaddr_inet())



