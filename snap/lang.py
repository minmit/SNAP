import functools
import itertools
import struct
import time
from ipaddr import IPv4Network
from bitarray import bitarray
import logging

from multiprocessing import Lock, Condition
import copy
import util
from util import *

NO_CACHE=False
NETKAT_CLASSIFIER_CACHE=True

basic_headers = ["srcmac", "dstmac", "srcip", "dstip", "tos", "srcport", "dstport",
                 "ethtype", "protocol"]
tagging_headers = ["vlan_id", "vlan_pcp"]
native_headers = basic_headers + tagging_headers
location_headers = ["switch", "inport", "outport"]
compilable_headers = native_headers + location_headers
content_headers = [ "raw", "header_len", "payload_len"]

################################################################################
# State Mapping and Log                                                        #
################################################################################
valid_value_types = [bool, int]
header_valid_types = [MAC, MAC, IPv4Network, IPv4Network, int, int, int, int, int, int,
                         int, int,
                                          int, int, int]

type_dict = dict(zip(compilable_headers, header_valid_types))


class InconsistenLogsError(Exception):

    def __str__(self):
        return "Logs are not consistent"
                    

class StateLog(object):

    entry_type = str

    def __init__(self, reads = set(), writes = set()):
        super(StateLog, self).__init__()
        self.reads = reads.difference(writes)
        self.writes = writes
       
    
    def addRead(self, state_var):
        assert isinstance(state_var, StateLog.entry_type)
        self.reads.add(state_var)

    def addWrite(self, state_var):
        assert isinstance(state_var, StateLog.entry_type)
        self.writes.add(state_var)
        self.reads.discard(state_var)

   
    def is_consistent(self, log_obj):
        assert isinstance(log_obj, StateLog)
        assert not log_obj is None
        assert not log_obj.writes is None
        assert not log_obj.reads is None
        return ( len(self.writes.intersection(log_obj.writes)) == 0
               and len(self.writes.intersection(log_obj.reads)) == 0
               and len(self.reads.intersection(log_obj.writes)) == 0)

    def union(self, log_obj):
        new_reads = self.reads.union(log_obj.reads)
        new_writes = self.writes.union(log_obj.writes)

        return StateLog(new_reads, new_writes)
        
    def __repr__(self):
        return str((self.reads, self.writes))

class StateMapping(object):  

    
    def __init__(self, state_var, key_type, value_type, default_value):

        ### type checks ###
        assert isinstance(key_type, tuple) and isinstance(value_type, tuple)
        assert reduce((lambda acc, x : acc and x in compilable_headers), key_type, True)
        assert reduce((lambda acc, x : acc and x in valid_value_types), value_type, True)
        assert self.same_type(default_value, value_type)
        ###################

        super(StateMapping, self).__init__()
        self.state_var = state_var
        self.key_type = key_type
        self.value_type = value_type
        self.default_value = default_value
        self.mapping = {}

    
    def same_type(self, value, typ):
        if not isinstance(value, tuple) or len(typ) != len(value):
            return False
        
        for t,v in zip(typ, value):
            
            if isinstance(t, type):
                if not isinstance(v, t):
                    return False
            elif not isinstance(v, type_dict[t]):
                return False

        return True


    def union(self, other):
        assert isinstance(other, StateMapping)
        assert self.state_var == other.state_var
        assert self.key_type == other.key_type
        assert self.value_type == other.value_type
        assert self.default_value == other.default_value

        self.mapping.update(other.mapping)

    def __getitem__(self, key):
        assert self.same_type(key, self.key_type)

        if not key in self.mapping:
            return self.default_value
        else:
            return self.mapping[key]

    def __setitem__(self, key, value):
        assert self.same_type(key, self.key_type)
        assert self.same_type(value, self.value_type)
        self.mapping[key] = value
                

    def __repr__(self):
        return str(self.mapping)

class PolicyState(object):
    current_state = None

    def __init__(self):
        self.state_map = {}


    def add_state_var(self, state_name, key_type, value_type, default_value):
        if not state_name in self.state_map:
            new_state = StateMapping(state_name, key_type, value_type, default_value)
            self.state_map[state_name] = new_state

    def __getitem__(self,key):
        return self.state_map[key]

    def union(self, policy_state):
        assert isinstance(policy_state, PolicyState)
        
        for key in self.state_map:
            if key in policy_state.state_map:
                self.state_map[key].union(policy_state.state_map[key])

        for key in policy_state.state_map:
            if not key in self.state_map:
                self.state_map[key] = copy.deepcopy(policy_state.state_map[key])

    def __repr__(self):
        return str(self.state_map)

    @classmethod
    def init_global_state(cls, init_state):
        cls.current_state = init_state


################################################################################
# Policy Language                                                              #
################################################################################

class Policy(object):
    """
    Top-level abstract class for policies.
    All Pyretic policies have methods for

    - evaluating on a single packet.
    - compilation to a switch Classifier
    """
    def eval(self, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        try:
            (state, pkts, log) = self.stateful_eval(PolicyState.current_state, pkt)
            PolicyState.current_state = state
            return pkts

        except Exception as ex: #TODO: look for a specific exception
            print traceback.format_exc()
            return {}

    def stateful_eval(self, state, pkt):
        raise NotImplementedError

    def __add__(self, pol):
        """
        The parallel composition operator.

        :param pol: the Policy to the right of the operator
        :type pol: Policy
        :rtype: Parallel
        """
        if isinstance(pol,parallel):
            return parallel([self] + pol.policies)
        else:
            return parallel([self, pol])

    def __rshift__(self, other):
        """
        The sequential composition operator.

        :param pol: the Policy to the right of the operator
        :type pol: Policy
        :rtype: Sequential
        """
        if isinstance(other,sequential):
            return sequential([self] + other.policies)
        else:
            return sequential([self, other])

    def __eq__(self, other):
        """Syntactic equality."""
        raise NotImplementedError

    def __ne__(self,other):
        """Syntactic inequality."""
        return not (self == other)

    def name(self):
        return self.__class__.__name__

    def __repr__(self):
        return "%s : %d" % (self.name(),id(self))


class Filter(Policy):
    """
    Abstact class for filter policies.
    A filter Policy will always either 

    - pass packets through unchanged
    - drop them

    No packets will ever be modified by a Filter.
    """
    def eval(self, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        raise NotImplementedError

    def __or__(self, pol):
        """
        The Boolean OR operator.

        :param pol: the filter Policy to the right of the operator
        :type pol: Filter
        :rtype: Union
        """
        if isinstance(pol,Filter):
            return union([self, pol])
        else:
            raise TypeError

    def __and__(self, pol):
        """
        The Boolean AND operator.

        :param pol: the filter Policy to the right of the operator
        :type pol: Filter
        :rtype: Intersection
        """
        if isinstance(pol,Filter):
            return intersection([self, pol])
        else:
            raise TypeError

    def __sub__(self, pol):
        """
        The Boolean subtraction operator.

        :param pol: the filter Policy to the right of the operator
        :type pol: Filter
        :rtype: Difference
        """
        if isinstance(pol,Filter):
            return difference(self, pol)
        else:
            raise TypeError

    def __invert__(self):
        """
        The Boolean negation operator.

        :param pol: the filter Policy to the right of the operator
        :type pol: Filter
        :rtype: negate
        """
        return negate([self])


class Singleton(Filter):
    """Abstract policy from which Singletons descend"""
    pass

 
@singleton
class identity(Singleton):
    """The identity policy, leaves all packets unchanged."""
    def stateful_eval(self, state, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        return (state, {pkt}, StateLog())

    def intersect(self, other):
        return other

    def covers(self, other):
        return True

    def __eq__(self, other):
        return ( id(self) == id(other)
            or ( isinstance(other, match) and len(other.map) == 0) )

    def __repr__(self):
        return "identity"

passthrough = identity   # Imperative alias
true = identity          # Logic alias
all_packets = identity   # Matching alias


@singleton
class drop(Singleton):
    """The drop policy, produces the empty set of packets."""
    def stateful_eval(self, state, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        return (state, set(), StateLog())

    def intersect(self, other):
        return self

    def covers(self, other):
        return False

    def __eq__(self, other):
        return id(self) == id(other)

    def __repr__(self):
        return "drop"

none = drop
false = drop             # Logic alias
no_packets = drop        # Matching alias


@singleton
class Controller(Singleton):
    def stateful_eval(self, state, pkt):
        return (state, set(), StateLog())

    def __eq__(self, other):
        return id(self) == id(other)

    def __repr__(self):
        return "Controller"
    

class match(Filter):
    """
    Match on all specified fields.
    Matched packets are kept, non-matched packets are dropped.

    :param *args: field matches in argument format
    :param **kwargs: field matches in keyword-argument format
    """
    def __init__(self, *args, **kwargs):

        def _get_processed_map(*args, **kwargs):
            map_dict = dict(*args, **kwargs)
            for field in ['srcip', 'dstip']:
                try:
                    val = map_dict[field]
                    map_dict.update({field: util.string_to_network(val)})
                except KeyError:
                    pass
            return map_dict

        if len(args) == 0 and len(kwargs) == 0:
            raise TypeError
        self.map = util.frozendict(_get_processed_map(*args, **kwargs))
        super(match,self).__init__()

    def stateful_eval(self, state, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        for field, pattern in self.map.iteritems():
            try:
                v = pkt[field]
                if not field in ['srcip', 'dstip']:
                    if pattern is None or pattern != v:
                        return (state, set(), StateLog())
                else:
                    v = util.string_to_IP(v)
                    if pattern is None or not v in pattern:
                        return (state, set(), StateLog())
            except Exception, e:
                if pattern is not None:
                    return (state, set(), StateLog())
        return (state, {pkt}, StateLog())

    def __eq__(self, other):
        return ( (isinstance(other, match) and self.map == other.map)
            or (other == identity and len(self.map) == 0) )

    def intersect(self, pol):

        def _intersect_ip(ipfx, opfx):
            most_specific = None
            if ipfx in opfx:
                most_specific = ipfx
            elif opfx in ipfx:
                most_specific = opfx
            else:
                most_specific = None
            return most_specific

        if pol == identity:
            return self
        elif pol == drop:
            return drop
        elif not isinstance(pol,match):
            raise TypeError
        fs1 = set(self.map.keys())
        fs2 = set(pol.map.keys())
        shared = fs1 & fs2
        most_specific_src = None
        most_specific_dst = None

        for f in shared:
            if (f=='srcip'):
                most_specific_src = _intersect_ip(self.map[f], pol.map[f])
                if most_specific_src is None:
                    return drop
            elif (f=='dstip'):
                most_specific_dst = _intersect_ip(self.map[f], pol.map[f])
                if most_specific_dst is None:
                    return drop
            elif (self.map[f] != pol.map[f]):
                return drop

        d = self.map.update(pol.map)

        if most_specific_src is not None:
            d = d.update({'srcip' : most_specific_src})
        if most_specific_dst is not None:
            d = d.update({'dstip' : most_specific_dst})

        return match(**d)

    def __and__(self,pol):
        if isinstance(pol,match):
            return self.intersect(pol)
        else:
            return super(match,self).__and__(pol)

    ### hash : unit -> int
    def __hash__(self):
        return hash(self.map)

    def covers(self,other):
        # Return identity if self matches every packet that other matches (and maybe more).
        # eg. if other is specific on any field that self lacks.
        if other == identity and len(self.map.keys()) > 0:
            return False
        elif other == identity:
            return True
        elif other == drop:
            return True
        if set(self.map.keys()) - set(other.map.keys()):
            return False
        for (f,v) in self.map.items():
            other_v = other.map[f]
            if (f=='srcip' or f=='dstip'):
                if v != other_v:
                    if not other_v in v:
                        return False
            elif v != other_v:
                return False
        return True

    def __repr__(self):
        return "match: %s" % ' '.join(map(str,self.map.items()))


class modify(Policy):
    """
    Modify on all specified fields to specified values.

    :param *args: field assignments in argument format
    :param **kwargs: field assignments in keyword-argument format
    """
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        if len(args) == 0 and len(kwargs) == 0:
            raise TypeError
        self.map = dict(*args, **kwargs)
        self.has_virtual_headers = not \
            reduce(lambda acc, f:
                       acc and (f in compilable_headers),
                   self.map.keys(),
                   True)
        super(modify,self).__init__()

    def stateful_eval(self, state, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """

        pkt_set = {pkt.modifymany(self.map)}
        return (state, pkt_set, StateLog())

    def __repr__(self):
        return "modify: %s" % ' '.join(map(str,self.map.items()))

    def __eq__(self, other):
        return ( isinstance(other, modify)
           and (self.map == other.map) )


################################################################################
# State Policies                                                               #
################################################################################

class matchState(Filter):

    def __init__(self, state_var, key_list, value_list):
        super(matchState, self).__init__()
        self.state_var = state_var
        self.key_list = key_list
        self.value_list = value_list

  
    def stateful_eval(self, state, pkt):
        
        def process_headers(f, v):
            if f in ['srcip', 'dstip']:
                return IPv4Network(v)
            else:
                return v

        grnd_key = tuple([process_headers(header, pkt[header]) for header in self.key_list])
        cur_value = state[self.state_var][grnd_key] 
        if cur_value == tuple(self.value_list):
            pkt_set = {pkt} 
        else:
            pkt_set = set()

        return (state, pkt_set, StateLog({self.state_var}, set()))


    def __repr__(self):
        return ("State %s[%s] = %s" 
                % (self.state_var, str(self.key_list), str(self.value_list)))

    def __eq__(self, other):
        return (isinstance(other, matchState)
                and self.state_var == other.state_var
                and self.key_list == other.key_list
                and self.value_list == other.value_list)



class setState(Policy):
    
    def __init__(self, state_var, key_list, value_list):
        super(setState, self).__init__()
        self.state_var = state_var
        self.key_list = key_list
        self.value_list = value_list

  
    def stateful_eval(self, state, pkt):
        def process_headers(f, pkt):
            if f in compilable_headers:
                if f in ['srcip', 'dstip']:
                    return IPv4Network(pkt[f])
                else:
                    return pkt[f]
            else:
                return f

        grnd_key = tuple([process_headers(header, pkt) for header in self.key_list])
        grnd_value = tuple([process_headers(header, pkt) for header in self.value_list])

        new_state = copy.deepcopy(state)

        new_state[self.state_var][grnd_key] = grnd_value

        return (new_state, {pkt}, StateLog(set(), {self.state_var}))

    def __repr__(self):
        return ("State %s[%s] <- %s" 
                % (self.state_var, str(self.key_list), str(self.value_list)))

    def __eq__(self, other):
        return (isinstance(other, setState)
                and self.state_var == other.state_var
                and self.key_list == other.key_list
                and self.value_list == other.value_list)


class Increment(Policy):
    
    def __init__(self, state_var, key_list, step):
        super(Increment, self).__init__()
        self.state_var = state_var
        self.key_list = key_list
        self.step = step

  
    def stateful_eval(self, state, pkt):
        def process_headers(f, pkt):
            if f in compilable_headers:
                if f in ['srcip', 'dstip']:
                    return IPv4Network(pkt[f])
                else:
                    return pkt[f]
            else:
                return f

        grnd_key = tuple([process_headers(header, pkt) for header in self.key_list])

        new_state = copy.deepcopy(state)

        new_state[self.state_var][grnd_key] += step

        return (new_state, {pkt}, StateLog(set(), {self.state_var}))

    def __repr__(self):
        return ("State %s[%s] <- %s" 
                % (self.state_var, str(self.key_list), str(self.step)))

    def __eq__(self, other):
        return (isinstance(other, Increment)
                and self.state_var == other.state_var
                and self.key_list == other.key_list
                and self.step == other.step)

################################################################################
# Combinator Policies                                                          #
################################################################################

class CombinatorPolicy(Policy):
    """
    Abstract class for policy combinators.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """
    ### init : List Policy -> unit
    def __init__(self, policies=[]):
        self.policies = list(policies)
        super(CombinatorPolicy,self).__init__()

    def __repr__(self):
        return "%s:\n%s" % (self.name(),util.repr_plus(self.policies))

    def __eq__(self, other):
        return ( self.__class__ == other.__class__
           and   self.policies == other.policies )


class negate(CombinatorPolicy,Filter):
    """
    Combinator that negates the input policy.

    :param policies: the policies to be negated.
    :type policies: list Filter
    """
    def stateful_eval(self, state, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        res = self.policies[0].stateful_eval(state, pkt)
        pkt_set = None
        if res[1]:
            pkt_set = set()
        else:
            pkt_set = {pkt}

        return (res[0], pkt_set, res[2])


class parallel(CombinatorPolicy):
    """
    Combinator for several policies in parallel.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """
    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return drop
        else:
            rv = super(parallel, self).__new__(parallel, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(parallel, self).__init__(policies)

    def __add__(self, pol):
        if isinstance(pol,parallel):
            return parallel(self.policies + pol.policies)
        else:
            return parallel(self.policies + [pol])

    def stateful_eval(self, state, pkt):
        """
        evaluates to the set union of the evaluation
        of self.policies on pkt

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        eval_res = map((lambda p : p.stateful_eval(state, pkt)), self.policies)

        if len(eval_res) == 0:
            return (state, set(), StateLog())

        (init_state, init_pkt_set, init_log)  = eval_res[0]
        res = (copy.deepcopy(init_state), init_pkt_set, init_log)

        for res_tuple in eval_res[1:]:
            new_log = res[2].union(res_tuple[2])
            new_pkt_set = res[1] | res_tuple[1]
            res[0].union(res_tuple[0])
            res = (res[0], new_pkt_set, new_log)

        return res

class union(parallel,Filter):
    """
    Combinator for several filter policies in parallel.

    :param policies: the policies to be combined.
    :type policies: list Filter
    """
    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return drop
        else:
            rv = super(parallel, self).__new__(union, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(union, self).__init__(policies)

    ### or : Filter -> Filter
    def __or__(self, pol):
        if isinstance(pol,union):
            return union(self.policies + pol.policies)
        elif isinstance(pol,Filter):
            return union(self.policies + [pol])
        else:
            raise TypeError


class sequential(CombinatorPolicy):
    """
    Combinator for several policies in sequence.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """
    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return identity
        else:
            rv = super(sequential, self).__new__(sequential, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(sequential, self).__init__(policies)

    def __rshift__(self, pol):
        if isinstance(pol,sequential):
            return sequential(self.policies + pol.policies)
        else:
            return sequential(self.policies + [pol])

    def stateful_eval(self, state, pkt):
        """
        evaluates to the set union of each policy in 
        self.policies on each packet in the output of the 
        previous.  The first policy in self.policies is 
        evaled on pkt.

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """

        prev_output = (state, {pkt}, StateLog())
        output = prev_output
        for policy in self.policies:
            if not prev_output[1]:
                return prev_output
            if policy == identity:
                continue
            if policy == drop:
                return (prev_output[0], set(), prev_output[2])
            
            res_pol = map((lambda p : policy.stateful_eval(prev_output[0], p)), list(prev_output[1]))
            new_state = copy.deepcopy(prev_output[0])
            new_pkt_set = set()
            new_log = StateLog()

            for (st, pkt_set, log) in res_pol:
                if not new_log.is_consistent(log):
                    raise InconsistenLogsError

                new_log = new_log.union(log)
                new_pkt_set = new_pkt_set | pkt_set
                new_state.union(st)
   
            new_log = new_log.union(prev_output[2])
            output = (new_state, new_pkt_set, new_log)
            prev_output = output
        
        return output


class intersection(sequential,Filter):
    """
    Combinator for several filter policies in sequence.

    :param policies: the policies to be combined.
    :type policies: list Filter
    """
    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return identity
        else:
            rv = super(sequential, self).__new__(intersection, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(intersection, self).__init__(policies)

    ### and : Filter -> Filter
    def __and__(self, pol):
        if isinstance(pol,intersection):
            return intersection(self.policies + pol.policies)
        elif isinstance(pol,Filter):
            return intersection(self.policies + [pol])
        else:
            raise TypeError


class if_(Policy):
    """
    if pred holds, t_branch, otherwise f_branch.

    :param pred: the predicate
    :type pred: Filter
    :param t_branch: the true branch policy
    :type pred: Policy
    :param f_branch: the false branch policy
    :type pred: Policy
    """
    def __init__(self, pred, t_branch, f_branch=identity):
        super(if_,self).__init__()
        self.pred = pred
        self.t_branch = t_branch
        self.f_branch = f_branch

    def stateful_eval(self, state, pkt):
        (pred_state, pkt_set, pred_log) = self.pred.stateful_eval(state, pkt)

        if pkt_set:
            branch_res = self.t_branch.stateful_eval(pred_state, pkt)
        else:
            branch_res = self.f_branch.stateful_eval(pred_state, pkt)

        (final_state, final_pkt_set, branch_log) = branch_res

        return (final_state, final_pkt_set, pred_log.union(branch_log))

    def __repr__(self):
        return "if\n%s\nthen\n%s\nelse\n%s" % (util.repr_plus([self.pred]),
                                               util.repr_plus([self.t_branch]),
                                               util.repr_plus([self.f_branch]))

    def __eq__(self, other):
        return (isinstance(other, if_) and 
                other.pred == self.pred and
                other.t_branch == self.t_branch and
                other.f_branch == self.f_branch)
