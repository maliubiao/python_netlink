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
    payload = netlink.generic_id_ctrl(hdr,0x12345) 
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

def get_iface():
    con = netlink.new_generic()
    hdr  = netlink.new_genlmsg(
            {
                "cmd": netlink.NL80211_CMD_GET_SCAN,
                "version": 0,
                "reserved": 0
                }
            ) 
    attr = netlink.newnlattr(netlink.NL80211_ATTR_IFINDEX, netlink.new_policy_u32(3)) 
    payload = netlink.generic_wireless(hdr+attr, 0x12345) 
    con.send(payload) 
    d = con.recv(4096)
    b = cStringIO.StringIO(d)
    msg = netlink.parse_nlmsg(b)
    mlen = b.tell() - 16 + msg["len"]
    payload = netlink.parse_genlmsg(b) 
    attrs = netlink.parse_attrs(b, mlen) 
    return {
            "msg": msg,
            "payload": payload,
            "attrs": attrs
            }
    

pprint.pprint(get_iface())



