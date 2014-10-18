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

import pprint 
ret = get_ifindex(3)
pprint.pprint(netlink.atod(ret["attrs"], netlink.ifla_attr_policy))

   
