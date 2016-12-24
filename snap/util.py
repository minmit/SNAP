from functools import wraps

from multiprocessing import Lock
from logging import StreamHandler
import sys
from ipaddr import IPv4Network, AddressValueError, IPv4Address
import time

def profile(f):
    @wraps(f)
    def time_wrapper(*args):
        t_s = time.time()
        res = f(*args)
        t_e = time.time()
        print f.__name__, t_e - t_s
        return res
    return time_wrapper           

def singleton(f):
    return f()

class frozendict(object):
    __slots__ = ["_dict", "_cached_hash"]

    def __init__(self, new_dict=None, **kwargs):
        self._dict = dict()
        if new_dict is not None:
            self._dict.update(new_dict)
        self._dict.update(kwargs)

    def update(self, new_dict=None, **kwargs):
        d = self._dict.copy()
        
        if new_dict is not None:
            d.update(new_dict)    
        d.update(kwargs)
        
        return self.__class__(d)

    def remove(self, ks):
        d = self._dict.copy()
        for k in ks:
            if k in d:
                del d[k]
        return self.__class__(d)
        
    def pop(self, *ks):
        result = []
        for k in ks:
            result.append(self[k])
        result.append(self.remove(*ks))
        return result
      
    def __repr__(self):
        return repr(self._dict)

    def __iter__(self):
        return iter(self._dict)

    def __contains__(self, key):
        return key in self._dict

    def keys(self):
        return self._dict.keys()

    def values(self):
        return self._dict.values()
        
    def items(self):
        return self._dict.items()

    def iterkeys(self):
        return self._dict.iterkeys()

    def itervalues(self):
        return self._dict.itervalues()
        
    def iteritems(self):
        return self._dict.iteritems()

    def get(self, key, default=None):
        return self._dict.get(key, default)

    def __getitem__(self, item):
        return self._dict[item]

    def __hash__(self):
        try:
            return self._cached_hash
        except AttributeError:
            h = self._cached_hash = hash(frozenset(self._dict.items()))
            return h
        
    def __eq__(self, other):
        return self._dict == other._dict

    def __ne__(self, other):
        return self._dict != other._dict
        
    def __len__(self):
        return len(self._dict)


def repr_plus(ss, indent=4, sep="\n", prefix=""):
    if isinstance(ss, basestring):
        ss = [ss]
    return indent_str(sep.join(prefix + repr(s) for s in ss), indent)    

def indent_str(s, indent=4):
    return "\n".join(indent * " " + i for i in s.splitlines())


def string_to_network(ip_str):
    """ Return an IPv4Network object from a dotted quad IP address/subnet. """
    try:
        return IPv4Network(ip_str)
    except AddressValueError:
        raise TypeError('Input not a valid IP address!')

def string_to_IP(ip_str):
    try:
        return IPv4Address(ip_str)
    except AddressValueError:
        raise TypeError('Input not a valid IP address!')

def network_to_string(ip_net):
    """ Return a dotted quad IP address/subnet from an IPv4Network object. """
    assert isinstance(ip_net, IPv4Network)
    if ip_net.prefixlen < 32:
        return str(ip_net.network) + '/' + str(ip_net.prefixlen)
    else:
        return str(ip_net.ip)

##############################################
####            Networking Utils          ####
##############################################


class EthAddr(object):
    def __init__(self, mac):

        # already a MAC object
        if isinstance(mac, EthAddr):
            self.bits = mac.bits

        # otherwise will be in byte or string encoding
        else:
            assert isinstance(mac, basestring)
            
            b = bitarray()

            # byte encoding
            if len(mac) == 6:
                b.frombytes(mac)

            # string encoding
            else:
                import re
                m = re.match(r"""(?xi)
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})
                             """, mac)
                if not m:
                    raise ValueError
                else:
                    b.frombytes(struct.pack("!BBBBBB", *(int(s, 16) for s in m.groups())))

            self.bits = b
        
    def to_bits(self):
        return self.bits

    def to01(self):
        return self.bits.to01()

    def to_bytes(self):
        return self.bits.tobytes()

    def __repr__(self):
        parts = struct.unpack("!BBBBBB", self.to_bytes())
        mac = ":".join(hex(part)[2:].zfill(2) for part in parts)
        return mac

    def __hash__(self):
        return hash(self.to_bytes())

    def __eq__(self,other):
        return repr(self) == repr(other)

    def __ne__(self, other):
        return not (self == other)

class MAC(EthAddr):
    pass


