import pdb
import netlink
import pprint
import cStringIO


def get_family():
    con = netlink.new_generic()
    hdr  = netlink.new_genlmsg(
            {
                "cmd": netlink.CTRL_CMD_GETFAMILY,
                "version": 0,
                "reserved": 0
                }
            ) 
    payload = netlink.generic_get_family(hdr,0x12345) 
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
            payload = netlink.parse_genlmsg(b) 
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


pprint.pprint(get_family())

