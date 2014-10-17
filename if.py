import netlink
import pdb
import pprint
import cStringIO

def get_ifindex(index): 
    con = netlink.new_route()
    con.send(netlink.route_getlink(index, 0x20141015))
    d = con.recv(4096) 
    b = cStringIO.StringIO(d)
    msg = netlink.parse_nlmsg(b)
    payload = netlink.parse_ifinfo(b)
    attrs = netlink.parse_attrs(b, len(d)) 
    con.close() 
    b.close()
    return {
            "msg": msg,
            "payload": payload,
            "attrs": attrs
            } 
def parse_msgs(msgs):
    ret = {}
    for m in msgs: 
        name, tp, parser = netlink.ifla_attr_policy[m["type"]] 
        if tp == netlink.NLA_NESTED: 
            ret[name] = parser(m)
        elif tp == netlink.NLA_STRUCT:
            b = cStringIO.StringIO(m["payload"])
            result = parser(b) 
            ret[name] = result
        else: 
            ret[name] = parser(m["payload"])
    pprint.pprint(ret)

import pprint 
ret = get_ifindex(3)
parse_msgs(ret["attrs"])

   
