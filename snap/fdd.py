from snap.lang import type_dict as td
from snap.lang import (identity, drop, match, modify, matchState,
                                    setState, Increment, negate, parallel, union, 
                                    sequential, intersection, if_)
from ipaddr import IPv4Network
from snap.util import MAC
from collections import Iterable
import copy
import itertools 

type_dict = copy.copy(td)
type_dict['id'] = str
type_dict['drop'] = str

# for extra policies
type_dict['sid'] = int
type_dict['agent'] = int
type_dict['smtp.MTA'] = int
type_dict['ftp.port'] = int
type_dict['tcpflags'] = int
type_dict['proto'] = int
type_dict['frametype'] = int
type_dict['apptype'] = int


field_rank = {'dstip' : 0, 'srcport' : 1, 'srcip' : 2, 'inport' : 3}
state_rank = {}

def is_number(x):
    return isinstance(x, (int, long, float, complex))

def is_iterable(x):
    return isinstance(x, (list, tuple)) and not isinstance(x, str)

def literal_cmp(e1, e2):
    '''
    compares e1 and e2, reversing
    the natural order in many cases.
    For instance, if both e1 and e2
    are numbers, literal_cmp(e1, e2)
    = cmp(e2, e1)
    '''
    
    if is_iterable(e1):
        if is_iterable(e2):
            if len(e1) != len(e2):
                return cmp(len(e2), len(e1))
            for (elem1, elem2) in zip(e1, e2):
                if elem1 == elem2:
                    continue
                return literal_cmp(elem1, elem2)
            return 0
        else:
            return -1
    elif is_iterable(e2):
        return 1
    else:
        if is_number(e1) and is_number(e2):
            return cmp(e2, e1)
        elif is_number(e1) and isinstance(e2, str):
            return 1
        elif is_number(e2) and isinstance(e1, str):
            return -1
        else:
            if e1 in field_rank and e2 in field_rank:
                return cmp(field_rank[e2], field_rank[e1])
            return cmp(e1, e2) ##TODO: can use fields order here

#########################################
#####             FDD               #####
#########################################

class FDD(object):
    
    def __init__(self):
        self.id = None
        self.string = None

    def set_id(self, new_id, x=None):
        if self.id is None:
            self.id = new_id
    
    def get_id(self):
        return self.id

    def level_repr(self, acc, shift):
        raise NotImplementedError

    def __str__(self):
        return str(self.string)
        
    
    def fdd_str(self):
        lrepr = self.level_repr([], '')
        return '\n'.join(lrepr) + "\n\n-------------------\n"

    def __hash__(self):
        return hash(str(self))

def asgn_id(fdd, num):
    '''
    traverses the fdd, setting fdd.id
    for each intermediate node and leaf 
    to a unique number
    '''

    if not fdd.id is None:
        return num
    if isinstance(fdd, Node):
        num = asgn_id(fdd.lchild, num)
        fdd.set_id(num)
        num = asgn_id(fdd.rchild, num + 1)
    elif isinstance(fdd, Leaf):
        fdd.set_id(num, 1)
        num += 1
    return num

#TODO: what is this exactly doing? I know why it is here but what exactly?
def asgn_smod(fdd):
    if isinstance(fdd, Node):
        t = fdd.test
        if isinstance(t, STest):
            lmod_dict = asgn_smod(fdd.lchild)
            rmod_dict = asgn_smod(fdd.rchild)
            t.smods = dict(lmod_dict.items() + rmod_dict.items())
            print '------------'
            print t
            print t.smods
            print '-----------'
            return t.smods
        else:
            asgn_smod(fdd.lchild)
            asgn_smod(fdd.rchild)
    elif isinstance(fdd, Leaf):
        res = {}
        for act_seq in fdd.act_info:
            (_, smods) = fdd.act_info[act_seq]
            res.update(smods)
        print '---------------'
        print fdd.__repr__()
        print res
        print '---------------'
        return res
    else:
        raise TypeError
    
#########################################
#####            Tests              #####
#########################################

class Node(FDD):
    def __init__(self, test, lchild, rchild):
        assert issubclass(test.__class__, Test)
        assert issubclass(lchild.__class__, FDD)
        assert issubclass(rchild.__class__, FDD)
        super(Node, self).__init__()
        self.test = test
        self.lchild = lchild
        self.rchild = rchild
        self.set_string()

    def set_string(self):
        self.string = 1 + self.rchild.string + self.lchild.string
        return

    def level_repr(self, acc, shift):
        acc.append(shift + str(self.id) + ": " + self.test.__repr__())
        acc = (self.lchild.level_repr(acc, shift + '\t'))
        acc = (self.rchild.level_repr(acc, shift + '\t')) 
        return acc

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.test == other.test and
                self.lchild == other.lchild and
                self.rchild == other.rchild)

    def __repr__(self):
        return self.test.__repr__()


class Test(object):

    def __init__(self, lh, rh):
        self.lh = lh
        self.rh = rh
        
    
    def __eq__(self, other):
        return (type(self) == type(other) and
                self.lh == other.lh and
                self.rh == other.rh)

    def __cmp__(self, other):
        raise NotImplementedError 
    
class FVTest(Test):
    
    def __init__(self, lh, rh):
        assert lh in type_dict
        assert isinstance(rh, type_dict[lh])
        super(FVTest, self).__init__(lh, rh)

    def __cmp__(self, other):
        if self == other:
            return 0
        
        if isinstance(other, FFTest) or isinstance(other, STest):
            return 1

        if not isinstance(other, FVTest):
            return -1

        if self.lh == other.lh:
            return literal_cmp(self.rh, other.rh)
        else:
            return literal_cmp(self.lh, other.lh)
    
    def __repr__(self):
        return '(%s = %s)' % (str(self.lh), str(self.rh))

class FFTest(Test):
    
    def __init__(self, lh, rh):
        assert lh in type_dict and rh in type_dict
        assert lh != rh
        assert type_dict[lh] == type_dict[rh]
        super(FFTest, self).__init__(lh, rh)

    
    def __cmp__(self, other):
        if self == other:
            return 0
        
        if isinstance(other, FVTest): 
            return -1
        
        if isinstance(other, STest):
            return 1

        if not isinstance(other, FFTest):
            return -1

        if self.lh == other.lh:
            return literal_cmp(self.rh, other.rh)
        else:
            return literal_cmp(self.lh, other.lh)

    def __repr__(self):
        return '(%s = %s)' % (str(self.lh), str(self.rh))

class STest(Test):
   
    def __init__(self, lh, rh):
        assert isinstance(lh, tuple) and len(lh) == 2
        assert isinstance(lh[0], str) and isinstance(lh[1], tuple)
        super(STest, self).__init__(lh, rh)
        self.var = lh[0]
        self.index = lh[1]
        self.smods = {}
    
    def __cmp__(self, other):
        if self == other:
            return 0
        
        if isinstance(other, FVTest) or isinstance(other, FFTest):
            return -1

        if not isinstance(other, STest):
            return -1

        if self.lh == other.lh:
            return literal_cmp(self.rh, other.rh)
        elif self.var == other.var:
            return literal_cmp(self.index, other.index)
        else:
            return literal_cmp(state_rank[self.var], state_rank[other.var])

    def __repr__(self):
        index_str = ','.join([str(x) for x in self.index])
        return '(%s[%s] = %s)' % (self.var, index_str, str(self.rh))

#########################################
#####           Actions             #####
#########################################

class Leaf(FDD):

    def __init__(self, act_set):
        super(Leaf, self).__init__()
        if len(act_set) == 0:
            raise TypeError
        self.act_set, self.act_info = self.refine_act_set(act_set)
        self.port_state_dict = None
        self.string = 1
        
        ## for assump
        self.assump_trace = None
 
    def refine_act_set(self, act_set):
        '''TODO: more refinement on neutral same field
        modifications
        act_info: for each act_seq, it has the field map,
        and a smods dictionary, which for each state variable
        holds the sequence of state modifications after refinement with 
        field modifications
        ref_act_set: refined action sequences to be used as the
        action set of the Leaf node
        '''

        ref_act_set = set()
        act_info = {}
        for act_seq in act_set:
            ref_act_seq = []
            fmap = {}
            smods = {}
            id_needed = False
            concrete_act_seen = False
            for act in act_seq:
                id_needed = False

                if isinstance(act, FAction):
                    if act.lh == 'id' and not concrete_act_seen:
                        id_needed = True
                    elif act.lh == 'drop':
                        ref_act_seq.append(act)
                        break
                    elif act.lh != 'id':
                        concrete_act_seen = True
                        fmap[act.lh] = act.rh
                        ref_act_seq.append(act)
                elif isinstance(act, SAction):
                    concrete_act_seen = True
                    state_var = act.var

                    # refining index based on fmap
                    new_index = []
                    for e in act.index:
                        if e in fmap:
                            new_index.append(fmap[e])
                        else:
                            new_index.append(e)
                    
                    # refining value based on fmap 
                    new_val = []
                    for e in act.rh:
                        if e in fmap:
                            new_val.append(fmap[e])
                        else:
                            new_val.append(e)
                    
                    if not state_var in smods:
                        smods[state_var] = tuple()
                    
                    ref_act = SAction((state_var, tuple(new_index)), tuple(new_val))
                    smods[state_var] += (ref_act,)
                    ref_act_seq.append(ref_act)
                
                elif isinstance(act, SInc):
                    concrete_act_seen = True
                    state_var = act.var

                    # refining index based on fmap
                    new_index = []
                    for e in act.index:
                        if e in fmap:
                            new_index.append(fmap[e])
                        else:
                            new_index.append(e)
                    
                    if not state_var in smods:
                        smods[state_var] = tuple()
                    
                    ref_act = SInc((state_var, tuple(new_index)), act.step)
                    smods[state_var] += (ref_act,)
                    ref_act_seq.append(ref_act)

            
            if id_needed and not concrete_act_seen:
                ref_act_seq.append(FAction('id', 'id'))
            if len(ref_act_seq) > 0:
                ref_act_seq = tuple(ref_act_seq)
                ref_act_set.add(ref_act_seq)
                act_info[ref_act_seq] = (fmap, smods)
        return frozenset(ref_act_set), act_info
            
    def level_repr(self, acc, shift):
        acc.append(shift + self.__repr__())
        #acc.append(shift + str(self.assump_trace))
        return acc

    def get_port_state_dict(self):
        '''
        Returns a dictionary from outports with its 
        corresponding set of actions and state modifications
        '''
        if self.port_state_dict is None:
            res = {}
            for act_seq in self.act_info:
                fmap, smods = self.act_info[act_seq]
                if 'outport' in fmap:
                    outport = fmap['outport']
                else:
                    outport = None
                if not outport in res:
                    res[outport] = ([], {})
                (fmods, smods_dict) = res[outport]
                fmods.append(fmap)
                # Because of consistency checks, we are sure
                # that this can be done without any action loss
                smods_dict.update(smods)
            for outport in res:
                (fmods, smods_dict) = res[outport]
                sorted_st = sorted(smods_dict.items(), lambda x,y : cmp(state_rank[x[0]], state_rank[y[0]])) # TODO: is this necessary?
                sorted_st = zip(*sorted_st)
                res[outport] += (sorted_st,)
            self.port_state_dict = res 
        return self.port_state_dict

    def seq(self, other, T):
        #TODO: can use T to refine more
        res = None
        for act_seq1 in self.act_set:
            if act_seq1[-1] == FAction('drop', 'drop'):
                new_leaf = Leaf(self.act_set)
            else:
                new_act_set = set()
                for act_seq2 in other.act_set:
                    if (act_seq2[0] == FAction('drop', 'drop') and
                            len(self.act_info[act_seq1][1]) == 0): #there are no state modifications
                        new_act_set.add(act_seq2)
                    else:
                        new_act_set.add(act_seq1 + act_seq2)
                new_leaf = Leaf(new_act_set)
            if res is None:
                res = new_leaf
            else:
                res = res.par(new_leaf, T)
        return res

    def is_drop(self):
        if len(self.act_set) == 1:
            (act, ) = self.act_set
            if len(act) == 1 and act[0] == FAction('drop', 'drop'):
                return True
        return False

    def par(self, other, T):
        if self.is_drop():
            return Leaf(other.act_set)
        if other.is_drop():
            return Leaf(self.act_set)

        new_act_set = self.act_set | other.act_set
        new_leaf = Leaf(new_act_set)
        
        seen = set()
        for act_seq in self.act_info:
                _, smods = self.act_info[act_seq]
                for s in smods:
                    if not s in seen:
                        seen.add(s)
                    else:
                        raise ContradictionError(msg = "possible parallel access to same state")

        return new_leaf

    def __invert__(self):
        if len(self.act_set) != 1:
            print self.act_set
            raise TypeError
        (act, ) = self.act_set
        if act[0] == FAction('id', 'id'):
            a = FAction('drop', 'drop')
            new_leaf = Leaf(frozenset([(a,)]))
            return new_leaf
        elif act[0] == FAction('drop', 'drop'):
            a = FAction('id', 'id')
            new_leaf = Leaf(frozenset([(a,)]))
            return new_leaf
        else:
            print self.act_set
            raise TypeError


    def get_outports(self):
        res = set()
        for act_seq in self.act_info:
            fmap, _ = self.act_info[act_seq]
            if 'outport' in fmap:
                res.add(fmap['outport'])
        return res

    def __eq__(self, other):
        res = isinstance(other, Leaf) and self.act_set == other.act_set
        return res 

    def __hash__(self):
        return hash(self.act_set)

    def __repr__(self):

        def tuple_repr(l):
            return '[' + ' ; '.join([e.__repr__() for e in l]) + ']'

        res = '{'
        res += ','.join([tuple_repr(x) for x in self.act_set])
        res += '}'
        return res

class Action(object):

    def __init__(self, lh, rh):
        super(Action, self).__init__()
        self.lh = lh
        self.rh = rh

    def __eq__(self, other):
        
        res = (type(self) == type(other) and
                self.lh == other.lh and 
                self.rh == other.rh) 
        return res
   
    def __hash__(self):
        return hash(self.__repr__())

    def __cmp__(self, other):
        if self == other:
            return 0
        elif not issubclass(other.__class__, Action):
            return -1
        elif self.lh == other.lh:
            return literal_cmp(self.rh, other.rh)
        else:
            return literal_cmp(self.lh, other.lh)

class FAction(Action):
    def __init__(self, lh, rh):
        assert lh in type_dict
        assert isinstance(rh, type_dict[lh])
        super(FAction, self).__init__(lh, rh)

    
    def __repr__(self):
        return '%s <- %s' % (str(self.lh), str(self.rh))


class SAction(Action):

    def __init__(self, lh, rh):
        assert isinstance(lh, tuple) and len(lh) == 2
        assert isinstance(lh[0], str) and isinstance(lh[1], tuple)
        super(SAction, self).__init__(lh, rh)
        self.var = lh[0]
        self.index = lh[1]

    def __repr__(self):
        index_str = ','.join([str(x) for x in self.index])
        return '%s[%s] <- %s' % (self.var, index_str, str(self.rh))

class SInc(Action):
    def __init__(self, lh, step):
        assert isinstance(lh, tuple) and len(lh) == 2
        assert isinstance(lh[0], str) and isinstance(lh[1], tuple)
        super(SInc, self).__init__(lh, step)
        self.var = lh[0]
        self.index = lh[1]
        self.step = step

    def __repr__(self):
        index_str = ','.join([str(x) for x in self.index])
        return '%s[%s] <- %s' % (self.var, index_str, str(self.step))

#########################################
#####         Translation           #####
#########################################
class ContradictionError(Exception):
    def __init__(self, k = None, v = None, t = None, msg = None):
        if msg is None and not (k is None and v is None and t is None):
            msg = ('Contradiction for %s and %s : %s' 
                        % (str(k), str(v), str(t)))
        super(ContradictionError, self).__init__(msg)

class RedundentError(Exception):
    def __init__(self, k, v):
        message = '%s already set to %s' % (str(k), str(v))
        super(ContradictionError, self).__init__(message)

class Trace(dict):
    '''
    If any of the fields in an equality set have a value,
    all of them will be assigned that value in the dictionary.
    There may be some fields that have equal values in the dictionary
    and are not in each other's equality sets.
    Invariant: no contradiction in the trace itself
    if a field equality or inequality is added, both sides are updates in
    corresponding dictionaries
    '''
    EQ = 0
    NEQ = 1
    BOTH = 2

    FIELD = 3
    VALUE = 4

    def __init__(self):
        super(Trace, self).__init__()
        self.fmap = {}
        self.eq_sets = {}
        self.neq_dict = {}
        self.fields = type_dict.keys()
    def __setitem__(self, key, val):
        if key in self.fmap:
            if self.fmap[key] == val:
                if val in self.neq_dict[key]:
                    #TODO: I think this can't happen
                    raise ContradictionError(key, val, self)
                else:
                    raise RedundentError(key, val)
            else:
                raise ContradictionError(key, val, self)
       
        if not key in self.neq_dict:
            self.neq_dict[key] = set()

        if key in self.eq_sets:
            for f in self.eq_sets[key]:
                self.fmap[f] = val
        else:
            self.eq_sets[key] = set([key])
            self.fmap[key] = val

    def update(self, key, val):
        if key in self.fmap:
            prev_val = self.fmap[key]
            if val != prev_val:
                self.fmap[key] = val
                self.neq_dict[key].discard(val)
                self.eq_sets[key].discard(key)
                self.eq_sets[key] = set([key])
        else:
            self[key] = val

    def __getitem__(self, key):
        return self.fmap[key]

    def merge_sets(self, f1, f2):
        new_eq_set = self.eq_sets[f1] | self.eq_sets[f2]
        for f in new_eq_set:
            self.eq_sets[f] = new_eq_set

    def add_field_equality(self, f1, f2):
        if f1 in self.eq_sets and f2 in self.eq_sets[f1]:
            return (None, None)
      
        if f1 in self.neq_dict and f2 in self.neq_dict[f1]:
            raise ContradictionError(f1, f2, self) 

        if f1 in self.fmap and f2 in self.fmap:
            if self[f1] == self[f2]:
                set1 = self.eq_sets[f1]
                set2 = self.eq_sets[f2]
                self.merge_sets(f1, f2)
                return (set1, set2)
            else:
                raise ContradictionError(f1, f2, self)

        elif f1 in self.fmap:
            self[f2] = self[f1]
        elif f2 in self.fmap:
            self[f1] = self[f2]
        else:
            if not f1 in self.eq_sets:
                self.eq_sets[f1] = set([f1])
            if not f2 in self.eq_sets:
                self.eq_sets[f2] = set([f2])
        set1 = self.eq_sets[f1]
        set2 = self.eq_sets[f2]
        self.merge_sets(f1, f2)
        return (set1, set2)

    def add_field_inequality(self, f1, f2):
        if f1 in self.neq_dict and f2 in self.neq_dict[f1]:
            return False

        if f1 in self.eq_sets and f2 in self.eq_sets[f1]:
            raise ContradictionError(f1, f2, self)
        
        if f1 in self.fmap and f2 in self.fmap and self[f1] == self[f2]:
            raise ContradictionError(f1, f2, self)
        
        if not f1 in self.neq_dict:
            self.neq_dict[f1] = set()
        if not f2 in self.neq_dict:
            self.neq_dict[f2] = set()

        self.neq_dict[f1].add(f2)
        self.neq_dict[f2].add(f1)
        return True
            
    def add_value_inequality(self, f, v):
        if f in self.neq_dict and v in self.neq_dict[f]:
            return False
        if f in self.fmap and self[f] == v:
            raise ContradictionError(f, v, self)

        if not f in self.neq_dict:
            self.neq_dict[f] = set()
        self.neq_dict[f].add(v)
        return True

    def get_type(self, elem):
        if elem in self.fields:
            return Trace.FIELD
        else:
            return Trace.VALUE
    
    def add_equality(self, e1, e2):
        type1 = self.get_type(e1)
        type2 = self.get_type(e2)
        if type1 == type2 and type1 == Trace.FIELD:
            val1 = None
            val2 = None
            if e1 in self.fmap and e2 in self.fmap:
                dtype = 1
                val1 = self.fmap[e1]
                val2 = self.fmap[e2]
            elif e1 in self.fmap:
                dtype = 2
                val1 = self.fmap[e1]
            elif e2 in self.fmap:
                dtype = 2
                val2 = self.fmap[e2]
            else:
                dtype = 3
            
            (set1, set2) = self.add_field_equality(e1, e2)
            digest = ((e1, e2, True), dtype, val1, val2, set1, set2)
            return [digest]
        elif type1 == Trace.FIELD and type2 == Trace.VALUE:
            set1 = None
            if e1 in self.eq_sets:
                dtype = 1
                set1 = self.eq_sets[e1]
            else:
                dtype = 2
            self[e1] = e2
            digest = ((e1, e2, True), dtype, set1)
            return [digest]
        elif type2 == Trace.FIELD and type1 == Trace.VALUE:
            set2 = None
            if e2 in self.eq_sets:
                dtype = 1
                set2 = self.eq_sets[e2]
            else:
                dtype = 2
            self[e2] = e1
            digest = ((e2, e1, True), dtype, set2)
            return [digest]
        else:
            raise TypeError
    
    def add_inequality(self, e1, e2):
        type1 = self.get_type(e1)
        type2 = self.get_type(e2)
        if type1 == type2 and type1 == Trace.FIELD:
            res = self.add_field_inequality(e1, e2)
        elif type1 == Trace.FIELD and type2 == Trace.VALUE:
            res = self.add_value_inequality(e1, e2)
        elif type2 == Trace.FIELD and type1 == Trace.VALUE:
            res = self.add_value_inequality(e2, e1)
        else:
            raise TypeError
        return [((e1, e2, False), res)]

    
    def revert(self, digests):
        for digest in digests:
            #print "reverting:", digest
            if digest is None:
                continue
            (e1, e2, holds) = digest[0]
            type1 = self.get_type(e1)
            type2 = self.get_type(e2)
            if holds:
                if type1 == type2 and type1 == Trace.FIELD:
                    (dtype, val1, val2, set1, set2) = digest[1:]
                    if set1 is None and set2 is None:
                        continue
                    if dtype == 1:
                        for f in set1:
                            self.eq_sets[f] = set1
                        for f in set2:
                            self.eq_sets[f] = set2
                    elif dtype == 2:
                        if val1 is None:
                            for f in set1:
                                del self.fmap[f]
                                self.eq_sets[f] = set1
                            for f in set2:
                                self.eq_sets[f] = set2
                        else:
                            assert val2 is None
                            for f in set2:
                                del self.fmap[f]
                                self.eq_sets[f] = set2
                            for f in set1:
                                self.eq_sets[f] = set1
                    elif dtype == 3:
                        for f in set1:
                            self.eq_sets[f] = set1
                        for f in set2:
                            self.eq_sets[f] = set2
                elif type1 == Trace.FIELD and type2 == Trace.VALUE:
                    (dtype, set1) = digest[1:]
                    if dtype == 1:
                        for f in set1:
                            del self.fmap[f]
                    else:
                        del self.fmap[e1]
            else:
                if type1 == type2 and type1 == Trace.FIELD:
                    self.neq_dict[e1].discard(e2)
                    self.neq_dict[e2].discard(e1)
                elif type1 == Trace.FIELD and type2 == Trace.VALUE:
                    self.neq_dict[e1].discard(e2)
                elif type2 == Trace.FIELD and type1 == Trace.VALUE:
                    self.neq_dict[e2].discard(e1)
                else:
                    raise TypeError
    

    def equal_field(self, f1, f2):
        if type_dict[f1] != type_dict[f2]:
            return Trace.NEQ
        if f1 in self.fmap and f2 in self.fmap:
            if self[f1] == self[f2]:
                '''if not f2 in self.eq_sets[f1]:
                    self.eq_sets[f1].add(f2)
                    self.eq_sets[f2] = self.eq_sets[f1]
                '''
                return Trace.EQ
            else:
                '''
                if not f2 in self.neq_dict[f1]:
                    self.neq_dict[f1].add(f2)
                    self.neq_dict[f2].add(f1)
                '''
                return Trace.NEQ
        elif f1 in self.eq_sets and f2 in self.eq_sets[f1]:
            return Trace.EQ
        elif f1 in self.neq_dict and f2 in self.neq_dict[f1]:
            return Trace.NEQ
        else:
            return Trace.BOTH

    def equal_value(self, f, v):
        if f in self.fmap:
            if self[f] == v:
                return Trace.EQ
            else:
                return Trace.NEQ
        elif f in self.neq_dict and v in self.neq_dict[f]:
            return Trace.NEQ
        else:
            return Trace.BOTH

    def equal(self, e1, e2):
        return self.equal_with_test(e1, e2)[0]

    def equal_with_test(self, e1, e2):
        if len(e1) != len(e2):
            return (Trace.NEQ, None)

        amb_seen = False
        test = None
        for (elem1, elem2) in zip(e1, e2):
            if elem1 == elem2:
                continue

            type1 = self.get_type(elem1)
            type2 = self.get_type(elem2)
            if type1 == type2:
                if type1 == Trace.FIELD:
                    f_eq = self.equal_field(elem1, elem2)
                    if f_eq == Trace.NEQ:
                        return (Trace.NEQ, None)
                    elif f_eq == Trace.BOTH:
                        amb_seen = True
                        test = FFTest(elem1, elem2)
                elif type1 == Trace.VALUE:
                    if elem1 != elem2:
                        return (Trace.NEQ, None)

            else:
                if type1 == Trace.FIELD:
                    field_elem = elem1
                    value_elem = elem2
                else:
                    field_elem = elem2
                    value_elem = elem1

                v_eq = self.equal_value(field_elem, value_elem)
                if v_eq == Trace.NEQ:
                    return (Trace.NEQ, None)
                elif v_eq == Trace.BOTH:
                    amb_seen = True
                    test = FVTest(field_elem, value_elem)
        if amb_seen:
            return (Trace.BOTH, test)
        else:
            return (Trace.EQ, None)

        
    def __str__(self):
        res = ''
        res += '-------- field map -----------\n'
        res += str(self.fmap)
        res += '\n--------- equality sets ---------- \n'
        res +=  str(self.eq_sets)
        res +=  '\n--------- non equalities ----------\n'
        res +=  str(self.neq_dict)
        res +=  '\n-----------------------------\n'
        return res

def fdd_str(fdd):
    return '\n'.join(fdd.level_repr([], ""))

class FDDTranslator(object):
    
    @classmethod
    def get_next_trace(cls, T, t, holds):
        #res = copy.deepcopy(T)
        digest = [None]
        if not isinstance(t, STest):
            if holds:
                digest = T.add_equality(t.lh, t.rh)
            else:
                digest = T.add_inequality(t.lh, t.rh)
        #print "generated digest: ", digest
        return digest

    @classmethod
    def refine_tree(cls, d, T):
        ''' refines/removes tests from the root
            of the FDD until a "non-trivial" test 
            or a leaf is reached.
        '''
        if isinstance(d, Leaf):
            return d
        elif isinstance(d, Node):
            t = d.test
            if isinstance(t, FVTest):
                res = T.equal([t.lh], [t.rh])
            elif isinstance(t, FFTest):
                res = T.equal([t.lh], [t.rh])
                if res == Trace.BOTH:
                    nl = t.lh
                    nr = t.rh
                    constr = FFTest
                    if t.rh in T:
                        nr = T[t.rh]
                        constr = FVTest
                    elif t.lh in T:
                        nl = t.rh
                        nr = T[t.lh]
                        constr = FVTest

                    d = Node(constr(nl, nr), d.lchild, d.rchild)
            
            elif isinstance(t, STest):
                nkey = []
                nvalue = []
                for e in t.index:
                    if e in T:
                        nkey.append(T[e])
                    else:
                        nkey.append(e)
                for e in t.rh:
                    if e in T:
                        nvalue.append(T[e])
                    else:
                        nvalue.append(e)
                res = Trace.BOTH
                d = Node(STest((t.var, tuple(nkey)), tuple(nvalue)), d.lchild, d.rchild)


            if res == Trace.EQ:
                return cls.refine_tree(d.lchild, T)
            elif res == Trace.NEQ:
                return cls.refine_tree(d.rchild, T)
            else:
                return d
        else:
            raise TypeError

    @classmethod
    def contradicting_tests(cls, t1, t2, T):
        ''' Tests have been changed to the 
        most specific format using information in T
        before use in this function, so they have
        both possible branches'''
        
        if t1 == t2:
            return False

        type1 = type(t1)
        type2 = type(t2)
        
        if type1 == type2:
            if type1 == FVTest:
                if T.equal([t1.lh], [t2.lh]) == Trace.EQ and t1.rh != t2.rh:
                    return True
                else:
                    return False

            if type1 == FFTest:
                f1 = [t1.lh]
                f2 = [t1.rh]
                f3 = [t2.lh]
                f4 = [t2.rh]
                if ( (T.equal(f1, f3) == Trace.EQ and T.equal(f2, f4) == Trace.NEQ) or
                     (T.equal(f1, f4) == Trace.EQ and T.equal(f2, f3) == Trace.NEQ) or
                     (T.equal(f2, f3) == Trace.EQ and T.equal(f1, f4) == Trace.NEQ) or
                     (T.equal(f2, f4) == Trace.EQ and T.equal(f1, f3) == Trace.NEQ)
                     ):
                    return True
                else:
                    return False
            elif type1 == STest:
                if ( t1.var == t2.var and T.equal(t1.index, t2.index) == Trace.EQ
                    and T.equal(t1.rh, t2.rh) == Trace.NEQ):
                    return True
                else:
                    return False
        return False

    @classmethod
    def equal_tests(cls, t1, t2, T):
        ''' Tests have been changed to the 
        most specific format using information in T
        before use in this function, so they have
        both possible branches'''

        if t1 == t2:
            return True

        type1 = type(t1)
        type2 = type(t2)
        if type1 == type2:
            if type1 == FFTest:
                if ((T.equal([t1.rh], [t2.rh]) == Trace.EQ and T.equal([t1.lh], [t2.lh]) == Trace.EQ)
                   or (T.equal([t1.rh], [t2.lh]) == Trace.EQ and T.equal([t1.lh], [t2.rh]) == Trace.EQ)):
                    return True
                else:
                    return False
            elif type1 == STest:
                if ( t1.var == t2.var and T.equal(t1.index, t2.index) == Trace.EQ
                    and T.equal(t1.rh, t2.rh) == Trace.EQ):
                    return True
                else:
                    return False
        return False

    @classmethod
    def act_seq(cls, act_seq, act_info, d, T):
        assert isinstance(d, Node)

        new_leaf = Leaf(set([act_seq]))
        if act_seq[-1] == FAction('drop', 'drop'):
            return new_leaf
        fmap = act_info[0]
        #new_T = copy.deepcopy(T)
        digests = []
        for f in fmap:
            digest = self.get_next_trace(T, FVTest(f, fmap[f]), True)
            digests.append(digest)
            #new_T.update(f, fmap[f])
        digests.reverse()
        new_T = T
        d = cls.refine_tree(d, new_T) 
        if isinstance(d, Node):
            t = d.test
            if isinstance(t, STest):
                state_var = t.var
                smods = act_info[1]
                if state_var in smods:
                    for sact in reversed(smods[state_var]):
                        (res, new_test) = new_T.equal_with_test(sact.index, t.index)
                        if res == Trace.EQ:
                            if isinstance(sact, SInc):
                                new_rh = (t.rh[0] - sact.step,)
                                t = STest(t.lh, new_rh)
                                continue
                            (res, new_test) = new_T.equal_with_test(sact.rh, t.rh)
                            if res == Trace.EQ:
                                res = cls.seq(new_leaf, d.lchild, new_T)
                                T.revert(digests)
                                return res
                            elif res == Trace.NEQ:
                                res = cls.seq(new_leaf, d.rchild, new_T)
                                T.revert(digests)
                                return res
                            else:
                                new_d = Node(new_test, d ,d)
                                res = cls.seq(new_leaf, new_d, new_T)
                                T.revert(digests)
                                return res
                        elif res == Trace.NEQ:
                            continue
                        else:
                            new_d = Node(new_test, d, d)
                            res = cls.seq(new_leaf, new_d, new_T)
                            T.revert(digests)
                            return res

            digest = cls.get_next_trace(new_T, t, True)
            lchild = cls.seq(new_leaf, d.lchild, new_T)
            new_T.revert(digest)
            lchild = cls.restrict(lchild, t, True, new_T)
            #print 'lchild'
            #print lchild
            digest = cls.get_next_trace(new_T, t, False)
            rchild = cls.seq(new_leaf, d.rchild, new_T)
            new_T.revert(digest)
            rchild = cls.restrict(rchild, t, False, new_T)
            #print 'rchild'
            #print rchild
            res = cls.par(lchild, rchild, new_T)
            T.revert(digests)
            return res
        elif isinstance(d, Leaf):
            return cls.seq(new_leaf, d, T)
        raise TypeError

    @classmethod
    def seq(cls, d1, d2, T):
        '''d1 = cls.refine_tree(d1, T)
        print '---- in seq ------'
        print '\n'.join(d1.level_repr([], ""))
        print '\n'.join(d2.level_repr([], ""))
        print 'T'
        print T
        '''
        if isinstance(d1, Node):
            #print 1 
            #TODO: maybe we can avoid adding d1.test to the Trace
            # because of the restrict afterwards...
            digest = cls.get_next_trace(T, d1.test, True)
            lseq = cls.seq(d1.lchild, d2, T)
            T.revert(digest)
            lseq = cls.restrict(lseq, d1.test, True, T)
            digest = cls.get_next_trace(T, d1.test, False)
            rseq = cls.seq(d1.rchild, d2, T)
            T.revert(digest)
            rseq = cls.restrict(rseq, d1.test, False, T)
            res = cls.par(lseq, rseq, T)
            return res
        elif isinstance(d1, Leaf):
            if isinstance(d2, Node):
                #print 2
                if d1.is_drop():
                    res = d1
                    return res
                
                res = None 
                for act_seq in d1.act_set:
                    p_res = cls.act_seq(act_seq, d1.act_info[act_seq], d2, T)
                    if res is None:
                        res = p_res
                    else:
                        res = cls.par(res, p_res, T)
                #print res
                return res
            elif isinstance(d2, Leaf):
                #print 3
                res = d1.seq(d2, T)
                #print res
                return res
            else:
                raise TypeError
        else:
            raise TypeError

    @classmethod
    def par(cls, d1, d2, T):
        d1 = cls.refine_tree(d1, T)
        d2 = cls.refine_tree(d2, T)
        #print '----- in par -----'
        #print fdd_str(d1) 
        #print fdd_str(d2
        #print T

        if isinstance(d1, Node):
            t1 = d1.test
            if isinstance(d2, Node):
                t2 = d2.test
                if cls.equal_tests(t1, t2, T):
                    digest = cls.get_next_trace(T, t1, True)
                    lchild = cls.par(d1.lchild, d2.lchild, T)
                    T.revert(digest)
                    digest = cls.get_next_trace(T, t1, False)
                    rchild = cls.par(d1.rchild, d2.rchild, T)
                    T.revert(digest)
                    test = t1
                else:
                    if t1 < t2:
                        d1, d2 = d2, d1
                        t1, t2 = t2, t1
                    
                    if cls.contradicting_tests(t1, t2, T):
                        digest = cls.get_next_trace(T, t1, True)
                        lchild = cls.par(d1.lchild, d2.rchild, T)
                        T.revert(digest)
                        digest = cls.get_next_trace(T, t1, False)
                        rchild = cls.par(d1.rchild, d2, T)
                        T.revert(digest)
                        test = t1
                    else:
                        digest = cls.get_next_trace(T, t1, True)
                        lchild = cls.par(d1.lchild, d2, T)
                        T.revert(digest)
                        digest = cls.get_next_trace(T, t1, False)
                        rchild = cls.par(d1.rchild, d2, T)
                        T.revert(digest)
                        test = t1
                         
            elif isinstance(d2, Leaf):
                digest = cls.get_next_trace(T, t1, True)
                lchild = cls.par(d1.lchild, d2, T)
                T.revert(digest)
                digest = cls.get_next_trace(T, t1, False)
                rchild = cls.par(d1.rchild, d2, T)
                T.revert(digest)
                test = t1
            else:
                raise TypeError
        elif isinstance(d1, Leaf):
            if isinstance(d2, Node):
                t2 = d2.test
                digest = cls.get_next_trace(T, t2, True)
                lchild = cls.par(d2.lchild, d1, T)
                T.revert(digest)
                digest = cls.get_next_trace(T, t2, False)
                rchild = cls.par(d2.rchild, d1, T)
                T.revert(digest)
                test = t2

            elif isinstance(d2, Leaf):
                return d1.par(d2, T)
            else:
                raise TypeError
        else: 
            raise TypeError
        
        if rchild == lchild:
            return lchild
        else:
            return Node(test, lchild, rchild)

    @classmethod
    def neg(cls, d):
        if isinstance(d, Node):
            lchild = cls.neg(d.lchild)
            rchild = cls.neg(d.rchild)
            return Node(d.test, lchild, rchild)
                    
        elif isinstance(d, Leaf):
            return ~d
        else:
            raise TypeError

    @classmethod
    def restrict(cls, d, t, holds, T):

        if not isinstance(t, STest):
            eq_res = T.equal([t.lh], [t.rh])
            if eq_res == Trace.EQ:
                if holds:
                    d = cls.refine_tree(d, T)
                    return d
                else:
                    return cls.get_drop()
            elif eq_res == Trace.NEQ:
                if holds:
                    return cls.get_drop()
                else:
                    d = cls.refine_tree(d, T)
                    return d

        d = cls.refine_tree(d, T)
        t = cls.refine_tree(Node(t, cls.get_id(), cls.get_drop()), T).test

        if isinstance(d, Node):
            if cls.equal_tests(t, d.test, T):
                if holds:
                    res = Node(t, d.lchild, cls.get_drop())
                else:
                    res = Node(t, cls.get_drop(), d.rchild)
            elif t > d.test:
                if cls.contradicting_tests(t, d.test, T):
                    if holds:
                        return Node(t, d.rchild, cls.get_drop())
                    else:
                        return Node(t, cls.get_drop(), d)
                else:
                    if holds:
                        return Node(t, d, cls.get_drop())
                    else:
                        return Node(t, cls.get_drop(), d)
            else:
                digest = cls.get_next_trace(T, d.test, False)
                rchild = cls.restrict(d.rchild, t, holds, T)
                T.revert(digest)
                if cls.contradicting_tests(t, d.test, T):
                    if holds:
                        res = Node(d.test, cls.get_drop(), rchild)
                    else:
                        res = Node(d.test, d.lchild, rchild)        
                else:
                    digest = cls.get_next_trace(T, d.test, True)
                    lchild = cls.restrict(d.lchild, t, holds, T)
                    T.revert(digest)
                    res = Node(d.test, lchild, rchild)
                                
        elif isinstance(d, Leaf):
            lchild = d
            rchild = cls.get_drop()
            if not holds:
                lchild, rchild = rchild, lchild
            
            res = Node(t, lchild, rchild)
        else:
            raise TypeError
        
        if res.lchild == res.rchild:
            return res.lchild
        else:
            return res

    @classmethod
    def get_id(cls):
        a = FAction('id', 'id')
        new_leaf = Leaf(frozenset([(a,)]))
        return new_leaf

    @classmethod
    def get_drop(cls):
        a = FAction('drop', 'drop')
        new_leaf = Leaf(frozenset([(a,)])) 
        return new_leaf

    @classmethod 
    def translate(cls, pol, T):
        if pol == identity:
            return cls.get_id()            
        if pol == drop:
            return cls.get_drop()

        typ = type(pol)
        if typ == match:
            fmap = pol.map.items()
            (f, v) = fmap[0]
            eq_res = T.equal_value(f, v) 
            if eq_res == Trace.BOTH:
                res = Node(FVTest(f, v), cls.get_id(), cls.get_drop())
            elif eq_res == Trace.EQ:
                return cls.get_id()
            else:
                return cls.get_drop()

            for (f, v) in fmap[1:]:
                eq_res = T.equal_value(f, v)
                if eq_res == Trace.NEQ:
                    return cls.get_drop()
                elif eq_res == Trace.EQ:
                    continue
                elif eq_res == Trace.BOTH:
                    new_match = Node(FVTest(f, v), cls.get_id(), cls.get_drop())
                    res = cls.seq(res, new_match, T)
            return res

        if typ == modify:
            fmap = pol.map.items()
            (f, v) = fmap[0]
            res = Leaf(frozenset([(FAction(f, v),)]))
            for (f, v) in fmap[1:]:
                new_mod = Leaf(frozenset([(FAction(f, v),)]))
                res = cls.seq(res, new_mod, T)
            return res

        if typ == matchState:
            res = Node(STest((pol.state_var, tuple(pol.key_list)), tuple(pol.value_list)),
                         cls.get_id(), cls.get_drop())
            return res

        if typ == setState:
            act = SAction((pol.state_var, tuple(pol.key_list)), tuple(pol.value_list))
            res = Leaf(frozenset([(act,)]))
            return res
        
        if typ == Increment:
            act = SInc((pol.state_var, tuple(pol.key_list)), pol.step)
            res = Leaf(frozenset([(act,)]))
            return res

        if typ == negate:
            inner_pol = cls.translate(pol.policies[0], T)
            return cls.neg(inner_pol)
       
        if issubclass(typ, parallel):
            res = cls.translate(pol.policies[0], T)            
            for p in pol.policies[1:]:
                p_fdd = cls.translate(p, T)
                res = cls.par(res, p_fdd, T)
            return res
        
        if issubclass(typ, sequential):
            res = cls.translate(pol.policies[0], T)
            for p in pol.policies[1:]:
                p_fdd = cls.translate(p, T)
                res = cls.seq(res, p_fdd, T)
            return res

        elif typ == if_:
            #print pol
            fa = cls.translate(pol.pred, T)
            #print 'fa:\n', fdd_str(fa)
            ft = cls.translate(pol.t_branch, T)
            #print 'ft:\n', fdd_str(ft)
            ff = cls.translate(pol.f_branch, T)
            #print 'ff:\n', fdd_str(ff)
            true_part = cls.seq(fa, ft, T)
            #print 'ture:\n', fdd_str(true_part)
            false_part = cls.seq(cls.neg(fa), ff, T)
            #print 'false:\n', fdd_str(false_part)
            return cls.par(true_part, false_part, T)
        raise TypeError


#########################################################
#####        State Requirement Extraction           #####
#########################################################
def augment_assump(assump, all_inports, inport_trace):
    if isinstance(assump, Node):
        t = assump.test
        if isinstance(t, FVTest):
            (eq, neq) = inport_trace
            new_eq = eq
            new_neq = neq
            if t.lh == 'inport':
                new_eq = {t.rh}
                new_neq = neq + [t.rh]
            augment_assump(assump.lchild, all_inports, (new_eq, neq))
            augment_assump(assump.rchild, all_inports, (eq, new_neq))
        else:
            raise TypeError
    else:
        (eq, neq) = inport_trace
        assump.assump_trace = (eq, neq)

def get_assump_inport_trace(assump, path):
    if isinstance(assump, Node):
        t = assump.test
        if isinstance(t, FVTest):
            (true_dict, false_set) = path
            (f, v) = (t.lh, t.rh)
            if f in true_dict:
                if true_dict[f] == v:
                    return get_assump_inport_trace(assump.lchild, path)
                else:
                    return get_assump_inport_trace(assump.rchild, path)
            elif (f, v) in false_set:
                return get_assump_inport_trace(assump.rchild, path)
            else:
                lres = get_assump_inport_trace(assump.lchild, path)
                rres = get_assump_inport_trace(assump.rchild, path)
                return (lres[0] | rres[0], lres[1] + rres[1])
        else:
            raise TypeError
    else:
        #print '-----------'
        #print path, assump.assump_trace
        #print '-----------'
        return assump.assump_trace
    
#TODO: more testing
def state_req(fdd, all_inports, inport_trace, states, st_req, 
              first, assump, path):
    #print fdd_str(fdd)
    #print st_req
    #print '--------------------'
    if isinstance(fdd, Node):
        t = fdd.test
        ttype = type(t)
        if ttype == FVTest:
            f = t.lh
            v = t.rh
            (true_dict, false_set) = path
            assert not f in true_dict
            true_dict[f] = v
            (eq, neq) = inport_trace
            new_eq = eq
            new_neq = neq
            if t.lh == 'inport':
                new_eq = {t.rh}
                new_neq = neq + [t.rh]
            state_req(fdd.lchild, all_inports, (new_eq, neq), states, st_req, 
                        first, assump, (true_dict, false_set))
            del true_dict[f]
            new_false = false_set | {(f, v)}
            state_req(fdd.rchild, all_inports, (eq, new_neq), states, st_req, 
                        first, assump, (true_dict, new_false))
        else:
            if first:
                (eq1, neq1) = get_assump_inport_trace(assump, path)
                (eq2, neq2) = inport_trace
                inport_trace = (eq1 | eq2 , neq1 + neq2)
            if ttype == STest:
                states.add(t.var)
                state_req(fdd.lchild, all_inports, inport_trace, states, st_req, False, None, None)
                state_req(fdd.rchild, all_inports, inport_trace, states, st_req, False, None, None)
                states.discard(t.var)
            else:
                state_req(fdd.lchild, all_inports, inport_trace, states, st_req, False, None, None)
                state_req(fdd.rchild, all_inports, inport_trace, states, st_req, False, None, None)
    
    elif isinstance(fdd, Leaf):
        if not fdd.is_drop():
            if first:
                (eq1, neq1) = get_assump_inport_trace(assump, path)
                (eq2, neq2) = inport_trace
                inport_trace = (eq1 | eq2 , neq1 + neq2)

            (eq, neq) = inport_trace
            inports = set()
            if len(eq) == 0:
                #inport = set() is considered impossible branch
                inports = all_inports - set(neq)
            else:
                inports = eq
            
            port_state_dict = fdd.get_port_state_dict()
            
            for outport in port_state_dict:
                m_states = set(port_state_dict[outport][1].keys())
                #if outport is None:
                #    pass 
                #else:
                if len(states | m_states) > 0:
                    for i in inports:
                        if not i in st_req:
                            st_req[i] = {}
                        if not outport in st_req[i]:
                            st_req[i][outport] = set()
                        st_req[i][outport] |= states | m_states
    else:
        raise TypeError

def get_st_req(fdd, all_inports, assump):
    st_req = {}
    state_req(fdd, set(all_inports), (set(), []), set(), st_req, True, assump, ({}, set()))
    return st_req


def get_state_info(fdd, state_info):
    if isinstance(fdd, Node):
        t = fdd.test
        if isinstance(t, STest):
            if not t.var in state_info:
                state_info[t.var] = len(t.index)
        get_state_info(fdd.lchild, state_info)
        get_state_info(fdd.rchild, state_info)
    elif isinstance(fdd, Leaf):
        for act_seq in fdd.act_info:
            _, smods = fdd.act_info[act_seq]
            for s in smods:
                if not s in state_info:
                    state_info[s] = len(smods[s][0].index)
    else:
        raise TypeError 
