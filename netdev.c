#include <Python.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <linux/if.h> 
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <netinet/in.h>
#include <errno.h>


PyDoc_STRVAR(netdev_ifconf_doc, "get network device interface information");

static PyObject *
netdev_ifconf(PyObject *object, PyObject *args)
{
	int ret;
	int fd; 
	struct ifreq *buffer;
	struct ifconf conf;
	unsigned long buffer_size = 1024;

	if(!PyArg_ParseTuple(args, "I|I:ifconf", &fd, &buffer_size)) {
		return NULL;	
	} 

	buffer = PyMem_Malloc(buffer_size);
	if (!buffer) {
		goto failed;
	}

	conf.ifc_len = buffer_size;
	conf.ifc_ifcu.ifcu_req = buffer;

	ret = ioctl(fd, SIOCGIFCONF, &conf);
	if (ret < 0) {
		goto failed; 
	}

	PyObject *ret_list = PyList_New(0);
				
	unsigned t = conf.ifc_len / sizeof(struct ifreq); 
	unsigned i;
	for(i=0; i < t; i++) { 
		struct ifreq *req = conf.ifc_ifcu.ifcu_req + i;
		PyObject *if_dict = PyDict_New();

		PyDict_SetItemString(if_dict, "name",
				PyString_FromString(req->ifr_name));

		struct sockaddr_in *addr = (void *)&req->ifr_addr;
		PyDict_SetItemString(if_dict, "addr",
			PyTuple_Pack(2, PyInt_FromLong(addr->sin_family),
			PyLong_FromUnsignedLong(addr->sin_addr.s_addr))); 
		PyList_Append(ret_list, if_dict);
	}

	PyMem_Free(buffer);
	return ret_list;

failed:
	PyErr_SetFromErrno(PyExc_OSError); 
	return NULL;
	
}


PyDoc_STRVAR(netdev_ifname_doc, "map an interface index to its name");

static PyObject *
netdev_ifname(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	unsigned ifindex;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "II:ifname", &fd, &ifindex)) {
		return NULL;
	}
	
	req.ifr_ifindex = ifindex;

	ret = ioctl(fd, SIOCGIFNAME, &req);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL; 
	}

	return PyString_FromString(req.ifr_name); 
}

PyDoc_STRVAR(netdev_ifflags_doc, "get interface flags");

static PyObject *
netdev_ifflags(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname; 
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "Is:iiflags", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	}

	strcpy(req.ifr_name, devname); 
	
	ret = ioctl(fd, SIOCGIFFLAGS, &req);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 

	return PyLong_FromUnsignedLong(req.ifr_flags); 
}

PyDoc_STRVAR(netdev_ifmtu_doc, "get the mtu of a device");

static PyObject *
netdev_ifmtu(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "Is:ifmtu", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	}

	strcpy(req.ifr_name, devname); 

	ret  = ioctl(fd, SIOCGIFMTU, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	return PyInt_FromLong(req.ifr_mtu);
}

PyDoc_STRVAR(netdev_ifmac_doc, "get the mac address of a device");

static PyObject *
netdev_ifmac(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "Is:ifmac", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	}

	strcpy(req.ifr_name, devname); 
	
	ret = ioctl(fd, SIOCGIFHWADDR, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL; 
	}

	return PyTuple_Pack(2, PyInt_FromLong(req.ifr_hwaddr.sa_family), PyByteArray_FromStringAndSize(req.ifr_hwaddr.sa_data, ETH_ALEN));
}

PyDoc_STRVAR(netdev_ifmap_doc, "get the device map of a device"); 

static PyObject *
netdev_ifmap(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "Is:ifmac", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	}

	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIFMAP, &req);
	
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	PyObject *ret_dict = PyDict_New();
	PyDict_SetItemString(ret_dict, "mem_start", PyLong_FromUnsignedLong(req.ifr_map.mem_start));
	PyDict_SetItemString(ret_dict, "mem_end", PyLong_FromUnsignedLong(req.ifr_map.mem_end));
	PyDict_SetItemString(ret_dict, "base_addr", PyLong_FromUnsignedLong(req.ifr_map.base_addr));
	PyDict_SetItemString(ret_dict, "irq", PyLong_FromUnsignedLong(req.ifr_map.irq));
	PyDict_SetItemString(ret_dict, "dma", PyLong_FromUnsignedLong(req.ifr_map.dma));
	PyDict_SetItemString(ret_dict, "port", PyLong_FromUnsignedLong(req.ifr_map.port));
	return ret_dict; 
}

PyDoc_STRVAR(netdev_ifindex_doc, "get the ifindex of a device");

static PyObject *
netdev_ifindex(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "Is:ifindex", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	}

	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIFINDEX, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	return PyInt_FromLong(req.ifr_ifindex); 
}


PyDoc_STRVAR(netdev_qlen_doc, "get the queue length of a device");

static PyObject *
netdev_qlen(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "Is:qlen", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	}

	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIFTXQLEN, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	return PyInt_FromLong(req.ifr_qlen);
}

PyDoc_STRVAR(netdev_setifname_doc, "change the name of a device");

static PyObject *
netdev_setifname(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname;
	char *newname;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "Iss:setifname", &fd, &devname, &newname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long newname");
		return NULL;
	}

	strcpy(req.ifr_name, devname);
	strcpy(req.ifr_name, newname);

	ret = ioctl(fd, SIOCSIFNAME, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	Py_RETURN_NONE;

	strcpy(req.ifr_name, devname); 

}

PyDoc_STRVAR(netdev_setifflags_doc, "set the flags of a devices");

static PyObject *
netdev_setifflags(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd;
	char *devname;
	unsigned long flags;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "Isk:setifflags", &fd, &devname, &flags)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 
	req.ifr_flags = flags;

	ret = ioctl(fd, SIOCSIFFLAGS, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	Py_RETURN_NONE; 
}

PyDoc_STRVAR(netdev_setifmtu_doc, "set the mtu of a device");

static PyObject *
netdev_setifmtu(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname;
	unsigned mtu;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "Isk:setifmtu", &fd, &devname, &mtu)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 
	req.ifr_mtu = mtu;

	ret = ioctl(fd, SIOCSIFFLAGS, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	Py_RETURN_NONE; 

}

PyDoc_STRVAR(netdev_setifmac_doc, "set the mac address of a device");

static PyObject *
netdev_setifmac(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd;
	char *devname;
	PyObject *mac_bytearray;
	struct ifreq req;

	if(!PyArg_ParseTuple(args, "IsO:setifmac", &fd, &devname, &mac_bytearray)) {
		return NULL; 
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	}

	if (!PyByteArray_Check(mac_bytearray)) {
		PyErr_SetString(PyExc_ValueError, "mtu must be a bytearray");
		return NULL;
	}
	if (PyByteArray_Size(mac_bytearray) < 6) {
		PyErr_SetString(PyExc_ValueError, "incorrected mac addr");
		return NULL;
	}

	strcpy(req.ifr_name, devname);
	
	ret = ioctl(fd, SIOCGIFHWADDR, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 

	memcpy(req.ifr_hwaddr.sa_data,
			PyByteArray_AsString(mac_bytearray), ETH_ALEN);

	ret = ioctl(fd, SIOCSIFHWADDR, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	Py_RETURN_NONE; 
}

PyDoc_STRVAR(netdev_setifqlen_doc, "set the queue length of a device");

static PyObject *
netdev_setifqlen(PyObject *object, PyObject *args)
{
	int ret;
	int fd; 
	char *devname;
	int qlen;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "IsI:setifqlen", &fd, &devname, &qlen)) {
		return NULL;
	}
	
	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 
	req.ifr_qlen = qlen;

	ret = ioctl(fd, SIOCSIFTXQLEN, &req);
	
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL; 
	}
	Py_RETURN_NONE; 
}



PyDoc_STRVAR(netdev_setifmap_doc, "set the device map of a device");

static PyObject *
netdev_setifmap(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname; 
	struct ifreq req;
	/* members of ifr_map */
	unsigned long mem_start;
	unsigned long mem_end;
	unsigned int base_addr;
	unsigned char dma;
	unsigned char irq;
	unsigned char port;

	if(!PyArg_ParseTuple(args, "Iskkbbb:setifmap", &fd, &devname, &mem_start, &mem_end, &base_addr, &dma, &irq, &port)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	req.ifr_map.mem_start = mem_start;
	req.ifr_map.mem_end = mem_end;
	req.ifr_map.base_addr = base_addr;
	req.ifr_map.irq = irq;
	req.ifr_map.dma = dma;
	req.ifr_map.port = port; 
	
	ret = ioctl(fd, SIOCSIFMAP, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	Py_RETURN_NONE; 
}

PyDoc_STRVAR(netdev_ifaddr_doc, "get interface address");

static PyObject *
netdev_ifaddr(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "Is:ifaddr", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIFADDR, &req);
	
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 
	struct sockaddr_in *in = (struct sockaddr_in *)&req.ifr_addr;

	return PyTuple_Pack(2, PyInt_FromLong(in->sin_family), PyLong_FromUnsignedLong(in->sin_addr.s_addr));
}


PyDoc_STRVAR(netdev_ifbcast_doc, "get the broadcast address");

static PyObject *
netdev_ifbcast(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname;
	struct ifreq req;
	
	if (!PyArg_ParseTuple(args, "Is:ifbcast", &fd, &devname)) {
		return NULL;
	} 

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIFBRDADDR, &req);
	
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 
	struct sockaddr_in *in = (struct sockaddr_in *)&req.ifr_addr;

	return PyTuple_Pack(2, PyInt_FromLong(in->sin_family), PyLong_FromUnsignedLong(in->sin_addr.s_addr));

}

PyDoc_STRVAR(netdev_ifdstaddr_doc, "get the destination address");

static PyObject *
netdev_ifdstaddr(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname;
	struct ifreq req;
	
	if (!PyArg_ParseTuple(args, "Is:ifdstaddr", &fd, &devname)) {
		return NULL;
	} 

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIFDSTADDR, &req);
	
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 
	struct sockaddr_in *in = (struct sockaddr_in *)&req.ifr_addr;

	return PyTuple_Pack(2, PyInt_FromLong(in->sin_family), PyLong_FromUnsignedLong(in->sin_addr.s_addr));

}

PyDoc_STRVAR(netdev_ifnetmask_doc, "get the the netmask for the interface");

static PyObject *
netdev_ifnetmask(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	char *devname;
	struct ifreq req;
	
	if (!PyArg_ParseTuple(args, "Is:ifdstaddr", &fd, &devname)) {
		return NULL;
	} 

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIFNETMASK, &req);
	
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 
	struct sockaddr_in *in = (struct sockaddr_in *)&req.ifr_addr;

	return PyTuple_Pack(2, PyInt_FromLong(in->sin_family), PyLong_FromUnsignedLong(in->sin_addr.s_addr));

} 

PyDoc_STRVAR(netdev_setifaddr_doc, "set interface address and family");

static PyObject *
netdev_setifaddr(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	unsigned family;
	char *devname;
	unsigned long addr;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "IsIk:setifaddr", &fd, &devname, &family, &addr)) {
		return NULL;
	} 

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	struct sockaddr_in *in = (struct sockaddr_in *)&req.ifr_addr;

	in->sin_addr.s_addr = addr; 
	in->sin_family = family;	

	ret = ioctl(fd, SIOCSIFADDR, &req);
	
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 

	Py_RETURN_NONE; 
}


PyDoc_STRVAR(netdev_setifbcast_doc, "set the broadcast address");

static PyObject *
netdev_setifbcast(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	unsigned family;
	char *devname;
	unsigned long addr;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "IsIk:setifbcast", &fd, &devname, &family, &addr)) {
		return NULL;
	} 

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	struct sockaddr_in *in = (struct sockaddr_in *)&req.ifr_addr;

	in->sin_addr.s_addr = addr; 
	in->sin_family = family;	

	ret = ioctl(fd, SIOCSIFBRDADDR, &req);
	
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 

	Py_RETURN_NONE; 
}

PyDoc_STRVAR(netdev_setifdstaddr_doc, "set the broadcast address");

static PyObject *
netdev_setifdstaddr(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	unsigned family;
	char *devname;
	unsigned long addr;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "IsIk:setifdstaddr", &fd, &devname, &family, &addr)) {
		return NULL;
	} 

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	struct sockaddr_in *in = (struct sockaddr_in *)&req.ifr_addr;

	in->sin_addr.s_addr = addr; 
	in->sin_family = family;	

	ret = ioctl(fd, SIOCSIFDSTADDR, &req);
	
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 

	Py_RETURN_NONE; 
}


PyDoc_STRVAR(netdev_setifnetmask_doc, "set the broadcast address");

static PyObject *
netdev_setifnetmask(PyObject *object, PyObject *args)
{
	int ret;
	int fd;
	unsigned family;
	char *devname;
	unsigned long addr;
	struct ifreq req;

	if (!PyArg_ParseTuple(args, "IsIk:setifnetmask", &fd, &devname, &family, &addr)) {
		return NULL;
	} 

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	struct sockaddr_in *in = (struct sockaddr_in *)&req.ifr_addr;

	in->sin_addr.s_addr = addr; 
	in->sin_family = family;	

	ret = ioctl(fd, SIOCSIFNETMASK, &req);
	
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 

	Py_RETURN_NONE; 
} 


PyDoc_STRVAR(netdev_iwstats_doc, "get wireless statistics");

static PyObject *
netdev_iwstats(PyObject *object, PyObject *args)
{
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;
	struct iw_statistics stats;

	if(!PyArg_ParseTuple(args, "Is:iwstats", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	/* kernel handler: wext-core.c ioctl_standard_iw_point */ 
	req.u.data.pointer = &stats;
	req.u.data.length = sizeof(struct iw_statistics);

	ret = ioctl(fd, SIOCGIWSTATS, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 

	PyObject *ret_dict = PyDict_New();

	PyDict_SetItemString(ret_dict, "status", PyInt_FromLong(stats.status));
	/* quality of the link */
	PyObject *qual_dict = PyDict_New();
	/* link quality */
	PyDict_SetItemString(qual_dict, "qual", PyInt_FromLong(stats.qual.qual));
	/* signal level (dBm)*/
	PyDict_SetItemString(qual_dict, "level", PyInt_FromLong(stats.qual.level));
	/* noise level (dBm)*/
	PyDict_SetItemString(qual_dict, "noise", PyInt_FromLong(stats.qual.noise));
	/* flags to know if updated */
	PyDict_SetItemString(qual_dict, "updated", PyInt_FromLong(stats.qual.updated));
	PyDict_SetItemString(ret_dict, "qual", qual_dict);
	/* packet discarded counts */
	PyObject *discard_dict = PyDict_New();
	/* wrong nwid/essid */
	PyDict_SetItemString(discard_dict, "nwid", PyLong_FromUnsignedLong(stats.discard.nwid));
	/* unable to code/decode (WEP) */ 
	PyDict_SetItemString(discard_dict, "code", PyLong_FromUnsignedLong(stats.discard.code));
	/* can't perform MAC reassembly */
	PyDict_SetItemString(discard_dict, "fragment", PyLong_FromUnsignedLong(stats.discard.fragment));
	/* max mac retries num reached */
	PyDict_SetItemString(discard_dict, "retries", PyLong_FromUnsignedLong(stats.discard.retries));
	/* oters cases */
	PyDict_SetItemString(discard_dict, "misc", PyLong_FromUnsignedLong(stats.discard.misc));
	PyDict_SetItemString(ret_dict, "discard", discard_dict);
	/* packet missed counts */
	PyDict_SetItemString(ret_dict, "missed_beacon", PyLong_FromUnsignedLong(stats.miss.beacon));

	return ret_dict; 
}

PyDoc_STRVAR(netdev_iwname_doc, "get the name of a wireless device");

static PyObject *
netdev_iwname(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;

	if(!PyArg_ParseTuple(args, "Is:iwname", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIWNAME, &req); 

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 

	return PyString_FromString(req.u.name); 
}

PyDoc_STRVAR(netdev_iwfreq_doc, "get frequency or channel: 0-1000 = channel, > 1000 = frequency in Hz");

static PyObject *
netdev_iwfreq(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;

	if(!PyArg_ParseTuple(args, "Is:iwfreq", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIWFREQ, &req); 

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 

	PyObject *ret_dict = PyDict_New();
	PyDict_SetItemString(ret_dict, "mantissa", PyInt_FromLong(req.u.freq.m));
	PyDict_SetItemString(ret_dict, "exponent", PyInt_FromLong(req.u.freq.e));
	PyDict_SetItemString(ret_dict, "flags", PyInt_FromLong(req.u.freq.flags));
	return ret_dict; 
}

PyDoc_STRVAR(netdev_iwmode_doc, "get operation mode");

static PyObject *
netdev_iwmode(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;

	if(!PyArg_ParseTuple(args, "Is:iwmode", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	memset(&req, 0, sizeof(req));
	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIWMODE, &req); 

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 

	return PyLong_FromUnsignedLong(req.u.mode);
}


static inline void
dict_add_param(PyObject *ret_dict, struct iw_param *param)
{ 
	PyDict_SetItemString(ret_dict, "value", PyInt_FromLong(param->value));
	PyDict_SetItemString(ret_dict, "fixed", PyInt_FromLong(param->fixed));
	PyDict_SetItemString(ret_dict, "disabled", PyInt_FromLong(param->disabled));
	PyDict_SetItemString(ret_dict, "flags", PyInt_FromLong(param->flags));

}

PyDoc_STRVAR(netdev_iwsens_doc, "get signal level threshold");

static PyObject *
netdev_iwsens(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;

	if(!PyArg_ParseTuple(args, "Is:iwsens", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIWSENS, &req); 

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 

	PyObject *ret_dict = PyDict_New();
	dict_add_param(ret_dict, &req.u.sens);	
	return ret_dict; 
}


PyDoc_STRVAR(netdev_iwrange_doc, "get range of parameters");

static PyObject *
netdev_iwrange(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;
	struct iw_range range;

	if(!PyArg_ParseTuple(args, "Is:iwrange", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	strcpy(req.ifr_name, devname); 
	bzero(&range, sizeof(range));
	
	req.u.data.pointer = &range;	
	req.u.data.length = sizeof(struct iw_range);
	req.u.data.flags = 0;

	ret = ioctl(fd, SIOCGIWRANGE, &req); 

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 
	
#define DICT_ADD_INT(x, y, z) PyDict_SetItemString(x, y, PyInt_FromLong(z))
#define DICT_ADD_ULONG(x, y, z) PyDict_SetItemString(x, y, PyLong_FromUnsignedLong(z))
	PyObject *ret_dict = PyDict_New();
	DICT_ADD_INT(ret_dict, "throughput", range.throughput);
	DICT_ADD_ULONG(ret_dict, "min_nwid", range.min_nwid);
	DICT_ADD_ULONG(ret_dict, "max_nwid", range.max_nwid); 
	DICT_ADD_ULONG(ret_dict, "old_num_channels", range.old_num_channels);	
	DICT_ADD_ULONG(ret_dict, "old_num_frequency", range.old_num_frequency); 
	DICT_ADD_ULONG(ret_dict, "scan-capa", range.scan_capa);
	DICT_ADD_INT(ret_dict, "sensitivity", range.sensitivity);	

	PyObject *max_qual_dict = PyDict_New();
	DICT_ADD_INT(max_qual_dict, "qual", range.max_qual.qual);
	DICT_ADD_INT(max_qual_dict, "level", range.max_qual.level);	
	DICT_ADD_INT(max_qual_dict, "noise", range.max_qual.noise);	
	DICT_ADD_INT(max_qual_dict, "updated", range.max_qual.updated);	
	PyDict_SetItemString(ret_dict, "max_qual", max_qual_dict);

	PyObject *avg_qual_dict = PyDict_New();
	DICT_ADD_INT(avg_qual_dict, "qual", range.avg_qual.qual);
	DICT_ADD_INT(avg_qual_dict, "level", range.avg_qual.level);	
	DICT_ADD_INT(avg_qual_dict, "noise", range.avg_qual.noise);	
	DICT_ADD_INT(avg_qual_dict, "updated", range.avg_qual.updated);	
	PyDict_SetItemString(ret_dict, "avg_qual", avg_qual_dict);

	if (range.num_bitrates < IW_MAX_BITRATES) {
		PyObject *rates = PyTuple_New(range.num_bitrates); 
		unsigned i;
		for(i=0; i < range.num_bitrates; i++) {
			PyTuple_SetItem(rates, i, PyInt_FromLong(range.bitrate[i]));
		} 
		PyDict_SetItemString(ret_dict, "bitrates", rates);
	}
	DICT_ADD_INT(ret_dict, "min_rts", range.min_rts);	
	DICT_ADD_INT(ret_dict, "max_rts", range.max_rts);
	DICT_ADD_INT(ret_dict, "min_frag", range.min_frag);
	DICT_ADD_INT(ret_dict, "max_frag", range.max_frag);
	DICT_ADD_INT(ret_dict, "min_pmp", range.min_pmp);
	DICT_ADD_INT(ret_dict, "max_pmp", range.max_pmp);
	DICT_ADD_INT(ret_dict, "min_pmt", range.min_pmt);
	DICT_ADD_INT(ret_dict, "max_pmt", range.max_pmt);
	DICT_ADD_INT(ret_dict, "pmp_flags", range.pmp_flags);
	DICT_ADD_INT(ret_dict, "pmt_flags", range.pmt_flags);
	DICT_ADD_INT(ret_dict, "pm_capa", range.pm_capa);
	if (range.num_encoding_sizes < IW_MAX_ENCODING_SIZES) {
		PyObject *ens = PyTuple_New(range.num_encoding_sizes);
		unsigned i;
		for(i=0; i < range.num_encoding_sizes; i++) {
			PyTuple_SetItem(ens, i, PyInt_FromLong(range.encoding_size[i]));
		}
		PyDict_SetItemString(ret_dict, "encoding_sizes", ens);
	}
	DICT_ADD_INT(ret_dict, "max_encoding_tokens", range.max_encoding_tokens);
	DICT_ADD_INT(ret_dict, "encoding_login_index", range.encoding_login_index);
	DICT_ADD_INT(ret_dict, "txpower_capa", range.txpower_capa);
	if (range.num_txpower < IW_MAX_TXPOWER) {
		PyObject *tx = PyTuple_New(range.num_txpower);
		unsigned i;
		for(i=0; i < range.num_txpower; i++) {
			PyTuple_SetItem(tx, i, PyInt_FromLong(range.txpower[i]));
		}
		PyDict_SetItemString(ret_dict, "txpowers", tx);
	}
	DICT_ADD_INT(ret_dict, "we_version_compiled", range.we_version_compiled);
	DICT_ADD_INT(ret_dict, "we_version_source", range.we_version_source);
	DICT_ADD_INT(ret_dict, "retry_capa", range.retry_capa);
	DICT_ADD_INT(ret_dict, "retry_flags", range.retry_flags);
	DICT_ADD_INT(ret_dict, "r_time_flags", range.r_time_flags);
	DICT_ADD_INT(ret_dict, "min_retry", range.min_retry);
	DICT_ADD_INT(ret_dict, "max_retry", range.max_retry);
	DICT_ADD_INT(ret_dict, "min_r_time", range.min_r_time);
	DICT_ADD_INT(ret_dict, "max_r_time", range.max_r_time);
	DICT_ADD_INT(ret_dict, "num_channels", range.num_channels);
	if (range.num_frequency < IW_MAX_FREQUENCIES) {
		PyObject *freqs = PyTuple_New(range.num_frequency);
		unsigned i;
		for(i=0; i < range.num_frequency; i++) {
			PyObject *freq_dict = PyDict_New();
			DICT_ADD_INT(freq_dict, "mantissa", range.freq[i].m);
			DICT_ADD_INT(freq_dict, "exponent", range.freq[i].e);
			DICT_ADD_INT(freq_dict, "index", range.freq[i].i);
			DICT_ADD_INT(freq_dict, "flags", range.freq[i].flags);
			PyTuple_SetItem(freqs, i, freq_dict); 
		}
		PyDict_SetItemString(ret_dict, "freqs", freqs);
	}
	DICT_ADD_INT(ret_dict, "enc_capa", range.enc_capa);
			
#undef DICT_ADD_INT
#undef DICT_ADD_ULONG
	return ret_dict; 
}


PyDoc_STRVAR(netdev_iwessid_doc, "get extended network name");

static PyObject *
netdev_iwessid(PyObject *object, PyObject *args)
{
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;
	char essid[IW_ESSID_MAX_SIZE + 1];

	if(!PyArg_ParseTuple(args, "Is:iwessid", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 
	
	strcpy(req.ifr_name, devname); 
	memset(essid, 0, sizeof(essid));
	
	req.u.essid.pointer = &essid;
	req.u.essid.length = IW_ESSID_MAX_SIZE + 1;
	req.u.essid.flags = 0;

	ret = ioctl(fd, SIOCGIWESSID, &req);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	return PyString_FromString(essid); 
}

PyDoc_STRVAR(netdev_iwnick_doc, "get nick name");

static PyObject *
netdev_iwnick(PyObject *object, PyObject *args)
{
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;
	char nick[IW_ESSID_MAX_SIZE+1];

	if(!PyArg_ParseTuple(args, "Is:iwnick", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 
	
	strcpy(req.ifr_name, devname); 
	memset(nick, 0, sizeof(nick));

	req.u.essid.pointer = &nick;
	req.u.essid.length = IW_ESSID_MAX_SIZE +1;
	req.u.essid.flags = 0;

	ret = ioctl(fd, SIOCGIWNICKN, &req);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	return PyString_FromStringAndSize(nick, req.u.data.length); 
}

PyDoc_STRVAR(netdev_iwap_doc, "get ap address");

static PyObject *
netdev_iwap(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;

	if(!PyArg_ParseTuple(args, "Is:iwap", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	memset(&req, 0, sizeof(req));	
	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIWAP, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL; 
	}

	return PyTuple_Pack(2, PyInt_FromLong(req.u.ap_addr.sa_family),
			PyByteArray_FromStringAndSize(req.u.ap_addr.sa_data, ETH_ALEN));

}


PyDoc_STRVAR(netdev_iwrate_doc, "get rate");

static PyObject *
netdev_iwrate(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;

	if(!PyArg_ParseTuple(args, "Is:iwrate", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	memset(&req, 0, sizeof(req));	
	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIWRATE, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL; 
	}

	return PyInt_FromLong(req.u.param.value); 
}

PyDoc_STRVAR(netdev_iwrts_doc, "get rts");

static PyObject *
netdev_iwrts(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;

	if(!PyArg_ParseTuple(args, "Is:iwrts", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	memset(&req, 0, sizeof(req));	
	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIWRTS, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	PyObject *ret_dict = PyDict_New();
	dict_add_param(ret_dict, &req.u.param); 
	return ret_dict;
}


PyDoc_STRVAR(netdev_iwfragrts_doc, "get fragment rts");

static PyObject *
netdev_iwfragrts(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;

	if(!PyArg_ParseTuple(args, "Is:iwfragrts", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	memset(&req, 0, sizeof(req));	
	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIWFRAG, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	PyObject *ret_dict = PyDict_New();
	dict_add_param(ret_dict, &req.u.param); 
	return ret_dict;
}


PyDoc_STRVAR(netdev_iwtxpow_doc, "get default transmit power");

static PyObject *
netdev_iwtxpow(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;

	if(!PyArg_ParseTuple(args, "Is:iwpxpow", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	memset(&req, 0, sizeof(req));	
	strcpy(req.ifr_name, devname); 

	ret = ioctl(fd, SIOCGIWTXPOW, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	PyObject *ret_dict = PyDict_New();
	dict_add_param(ret_dict, &req.u.txpower); 
	return ret_dict;
}

PyDoc_STRVAR(netdev_iwretry_doc, "get  retry limit");

static PyObject *
netdev_iwretry(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	long sv;
	long lv;
	char *devname; 
	struct iwreq req;

	if(!PyArg_ParseTuple(args, "Is:iwretry", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	memset(&req, 0, sizeof(req));	
	strcpy(req.ifr_name, devname); 

	/* for short value */
	req.u.retry.flags = 0;
	
	ret = ioctl(fd, SIOCGIWRETRY, &req);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	} 
	sv = req.u.retry.value;	

	req.u.retry.flags = IW_RETRY_LONG;
	/* for long value */ 
	ret = ioctl(fd, SIOCGIWRETRY, &req);
	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	lv = req.u.retry.value;
	
	return PyTuple_Pack(2, PyInt_FromLong(sv), PyInt_FromLong(lv));
}

PyDoc_STRVAR(netdev_iwencode_doc, "get key");

static PyObject *
netdev_iwencode(PyObject *object, PyObject *args)
{
	int ret;
	int fd; 
	char *devname; 
	char key[IW_ENCODING_TOKEN_MAX];
	struct iwreq req;

	if(!PyArg_ParseTuple(args, "Is:iwretry", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	memset(&req, 0, sizeof(req));	
	strcpy(req.ifr_name, devname); 

	req.u.data.pointer = &key;
	req.u.data.length = IW_ENCODING_TOKEN_MAX;
	req.u.data.flags = 0;

	ret = ioctl(fd, SIOCGIWENCODE, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	if (req.u.data.length > IW_ENCODING_TOKEN_MAX) {
		return PyString_FromStringAndSize(key, IW_ENCODING_TOKEN_MAX);
	} else {
		return PyString_FromStringAndSize(key, req.u.data.length);
	} 
}


PyDoc_STRVAR(netdev_iwpower_doc, "get power management status");

static PyObject *
netdev_iwpower(PyObject *object, PyObject *args)
{ 
	int ret;
	int fd; 
	char *devname; 
	struct iwreq req;
	

	if(!PyArg_ParseTuple(args, "Is:iwpower", &fd, &devname)) {
		return NULL;
	}

	if (strlen(devname) > IFNAMSIZ) {
		PyErr_SetString(PyExc_ValueError, "insanly long devname");
		return NULL;
	} 

	memset(&req, 0, sizeof(req));	
	strcpy(req.ifr_name, devname); 
	req.u.power.flags = 0;

	ret = ioctl(fd, SIOCGIWPOWER, &req);

	if (ret < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	PyObject *ret_dict = PyDict_New();
	dict_add_param(ret_dict, &req.u.power); 
	return ret_dict;
}




static PyMethodDef netdev_methods[] = {
	{"ifconf", (PyCFunction)netdev_ifconf,
		METH_VARARGS, netdev_ifconf_doc},
	{"ifname", (PyCFunction)netdev_ifname,
		METH_VARARGS, netdev_ifname_doc},
	{"ifflags", (PyCFunction)netdev_ifflags,
		METH_VARARGS, netdev_ifflags_doc},
	{"ifmtu", (PyCFunction)netdev_ifmtu,
		METH_VARARGS, netdev_ifmtu_doc},
	{"ifmac", (PyCFunction)netdev_ifmac,
		METH_VARARGS, netdev_ifmac_doc},
	{"ifmap", (PyCFunction)netdev_ifmap,
		METH_VARARGS, netdev_ifmap_doc},
	{"ifindex", (PyCFunction)netdev_ifindex,
		METH_VARARGS, netdev_ifindex_doc},
	{"ifqlen", (PyCFunction)netdev_qlen,
		METH_VARARGS, netdev_qlen_doc}, 
	{"setifname", (PyCFunction)netdev_setifname,
		METH_VARARGS, netdev_setifname_doc},
	{"setifflags", (PyCFunction)netdev_setifflags,
		METH_VARARGS, netdev_setifflags_doc},
	{"setifmtu", (PyCFunction)netdev_setifmtu,
		METH_VARARGS, netdev_setifmtu_doc},
	{"setifmac", (PyCFunction)netdev_setifmac,
		METH_VARARGS, netdev_setifmac_doc}, 
	{"setifqlen", (PyCFunction)netdev_setifqlen,
		METH_VARARGS, netdev_setifqlen_doc},
	{"setifmap", (PyCFunction)netdev_setifmap,
		METH_VARARGS, netdev_setifmap_doc},
	{"ifaddr", (PyCFunction)netdev_ifaddr,
		METH_VARARGS, netdev_ifaddr_doc},
	{"ifbcast", (PyCFunction)netdev_ifbcast,
		METH_VARARGS, netdev_ifbcast_doc},
	{"ifdstaddr", (PyCFunction)netdev_ifdstaddr,
		METH_VARARGS, netdev_ifdstaddr_doc},
	{"ifnetmask", (PyCFunction)netdev_ifnetmask,
		METH_VARARGS, netdev_ifnetmask_doc},
	{"setifaddr", (PyCFunction)netdev_setifaddr,
		METH_VARARGS, netdev_setifaddr_doc},
	{"setifbcast", (PyCFunction)netdev_setifbcast,
		METH_VARARGS, netdev_setifbcast_doc},
	{"setifdstaddr", (PyCFunction)netdev_setifdstaddr,
		METH_VARARGS, netdev_setifdstaddr_doc},
	{"setifnetmask", (PyCFunction)netdev_setifnetmask,
		METH_VARARGS, netdev_setifnetmask_doc},
	{"iwstats", (PyCFunction)netdev_iwstats,
		METH_VARARGS, netdev_iwstats_doc},
	{"iwname", (PyCFunction)netdev_iwname,
		METH_VARARGS, netdev_iwname_doc},
	{"iwfreq", (PyCFunction)netdev_iwfreq,
		METH_VARARGS, netdev_iwfreq_doc},
	{"iwmode", (PyCFunction)netdev_iwmode,
		METH_VARARGS, netdev_iwmode_doc},
	{"iwsens", (PyCFunction)netdev_iwsens,
		METH_VARARGS, netdev_iwsens_doc},
	{"iwrange", (PyCFunction)netdev_iwrange,
		METH_VARARGS, netdev_iwrange_doc},
	{"iwessid", (PyCFunction)netdev_iwessid,
		METH_VARARGS, netdev_iwessid_doc},
	{"iwnick", (PyCFunction)netdev_iwnick,
		METH_VARARGS, netdev_iwnick_doc},
	{"iwap", (PyCFunction)netdev_iwap,
		METH_VARARGS, netdev_iwap_doc},
	{"iwrate", (PyCFunction)netdev_iwrate,
		METH_VARARGS, netdev_iwrate_doc},
	{"iwrts", (PyCFunction)netdev_iwrts,
		METH_VARARGS, netdev_iwrts_doc},
	{"iwfragrts", (PyCFunction)netdev_iwfragrts,
		METH_VARARGS, netdev_iwfragrts_doc},
	{"iwtxpow", (PyCFunction)netdev_iwtxpow,
		METH_VARARGS, netdev_iwtxpow_doc},
	{"iwretry", (PyCFunction)netdev_iwretry,
		METH_VARARGS, netdev_iwretry_doc},
	{"iwencode", (PyCFunction)netdev_iwencode,
		METH_VARARGS, netdev_iwencode_doc},
	{"iwpower", (PyCFunction)netdev_iwpower,
		METH_VARARGS, netdev_iwpower_doc}, 
	{NULL, NULL, 0, NULL}
};


PyMODINIT_FUNC initnetdev(void)
{
	Py_InitModule("netdev", netdev_methods); 
}
