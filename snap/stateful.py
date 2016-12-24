import random
import time
import pickle

from snap.lang import *
from snap.state_dep import st_dep
from snap import fdd
from snap import rule_gen as gen
from snap.util import profile

##################################
####     Compiler-Phase1      ####
##################################

none_traffic = 0.1
none_cap = 100000

def add_none_node(graph, pv):
    prev_nodes = graph.nodes()
    graph.add_node(pv, edge_in = False, edge_out = True)
    for n in prev_nodes:
        if (not graph.node[n]['edge_in']) and (not graph.node[n]['edge_out']):
            graph.add_edge(n, pv, c = none_cap)

def revise_st_req(st_req, ports, graph, traffic_req):
    """ looks like we need to
        put the 'p' back at the 
        beginning of ports.
        if we have a non-port, adjust the graph, st_req, and
        traffic_req accordingly.
    """
    none_node_added = False
    none_port = max(ports) + 1
    
    res = {}
    for u in st_req:
        pu = 'p%d' % u
        #pu = u
        for v in st_req[u]:
            if v is None:
                pv = 'p%d' % none_port
                if not none_node_added:
                    none_node_added = True
                    add_none_node(graph, pv)
                    ports.append(none_port)
                traffic_req[pu, pv] = none_traffic
                edges = [d for x,_,d in graph.edges(data=True) if x == pu]
                for d in edges:
                    d['c'] += none_traffic
            else:
                pv = 'p%d' % v
                #pv = v
            res[pu, pv] = st_req[u][v]
    return res

def compile_to_req(pol, assumptions, ports,
                   graph, traffic_req):
    (tied, dep, rank) = st_dep(pol)
    
    print "dep", dep
    print "tied", tied
    @profile
    def fdd_trans():
        fdd.state_rank = rank
        pol_fdd = fdd.FDDTranslator.translate(pol, fdd.Trace()) 
        fdd.asgn_id(pol_fdd, 0)
        assump = fdd.FDDTranslator.translate(assumptions, fdd.Trace())
        return pol_fdd, assump
   
    (pol_fdd, assump) = fdd_trans()
    
    print fdd.fdd_str(pol_fdd)

    @profile
    def st_req():
        fdd.augment_assump(assump, ports, (set(), []))
        res = fdd.get_st_req(pol_fdd, ports, assump)
        return revise_st_req(res, ports, graph, traffic_req)
    
    state_req = st_req()
    print "state_req", state_req
    return (state_req, rank.keys(), dep, tied, 
            pol_fdd, rank)

##################################
####     Compiler-Phase2      ####
##################################


def compile_from_req(topo, traffic_req, st_req, states, dep, tied, 
                        stateful=True, timelimit=None):
    
    
    from snap.mip import create_mip, optimize_mip
    
    ilp = create_mip(topo, traffic_req, st_req, states, dep, tied, stateful) 
    
    m = ilp[0]
   
    # Exploring different parameters
 
    m.params.Method = 3
    m.params.OptimalityTol = 1e-2  
    m.params.CutPasses = 1

    
    # Code for Tuning
    

    if not timelimit is None:
        m.params.TimeLimit = timelimit
    optimize_mip(ilp[0])
    (R, PS, sw_ie, st_to_flow, p_sw) = ilp[1:]
 
    
    # Code for checking performance of dynamic
    # change to the optimization problem

    R = dict([(ind, R[ind].x) for ind in R])
    PS = dict([(ind, PS[ind].x) for ind in PS])  
    return (R, PS, sw_ie, st_to_flow, p_sw)

##################################
####     Compiler-Phase3      ####
##################################

def get_port_map(topo):
    port_map = {}
    for n in topo.nodes():
        neis = topo.neighbors(n)
        port_map[n] = dict(zip(neis, range(1, len(neis) + 1)))
    return port_map

def get_state_map(PS):
    res = {}
    res2 = {}
    for (s, n) in PS:
        if PS[s, n] == 1:
            res[s] = n
            if not n in res2:
                res2[n] = []
            res2[n].append(s)
    return (res, res2)

def get_state_port(st_to_flow, dep):
    res = {}
    for s in st_to_flow:
        res[s] = {}
        for (u, v) in st_to_flow[s]:
            u = u[1:]
            v = v[1:]
            if not u in res[s]:
                res[s][u] = []
            res[s][u].append(v)
    return res

def get_inports(topo, n, port_map):
    inports = []
    neis = topo.neighbors(n)
    for nei in neis:
        if topo.node[nei]['edge_in']:
            inports.append(port_map[n][nei])        
    return inports

def is_edge(topo, n):
    for nei in topo.neighbors(n):
        if topo.node[nei]['edge_in']:
            return True
    return False

@profile
def rule_gen(topo, ilp, dep, pol_fdd, state_rank):
    (R, PS, sw_ie, st_to_flow, p_sw) = ilp
    sw_in = zip(*sw_ie)[0]
    p_sw = list(p_sw)
    target = p_sw[0]
     
    port_map = get_port_map(topo)
    (state_sw_map, sw_state_map) = get_state_map(PS)
    state_port = get_state_port(st_to_flow, dep)

    st_targets = [x for x in sw_state_map.keys() if x in p_sw]
    st_edge_targets = [x for x in st_targets if is_edge(topo, x)]
    if len(st_edge_targets) > 0:
        targets = [st_edge_targets[0]]
    else:
        targets = [st_targets[0]]

    for target in targets:
        states = set(sw_state_map[target] if target in sw_state_map else [])
        inports = get_inports(topo, target, port_map)
     
        gen.generate_dataplane(target, pol_fdd, inports, states, state_rank,
                                    state_sw_map, state_port, len(inports) > 0,
                                    port_map, R,
                                    "./rules/dataplane_%s.py" % target, "./rules/commands_%s" % target)

