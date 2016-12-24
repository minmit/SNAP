from gurobipy import *
import itertools
from networkx import write_dot
#import webcolors
#import colorsys
from networkx import DiGraph
from time import time
import pickle

def state_dict(st_req, sw_ie):
    res = {}
    for (u, v) in st_req:
        if (u, v) in sw_ie:
            state_set = st_req[u, v]
            for s in state_set:
                if not s in res:
                    res[s] = set()
                res[s].add((u, v))
    return res

def req_dep_dict(st_to_flow, dep):
    res = {}
    for (s1, s2) in dep:
        f1 = st_to_flow[s1]
        f2 = st_to_flow[s2]
        for flow in f1:
            if flow in f2:
                if not flow in res:
                    res[flow] = {}
                if not s1 in res[flow]:
                    res[flow][s1] = []
                res[flow][s1].append(s2)
    return res


def create_mip(topo, traffic_req, st_req, states, state_dep, Ps):
    '''
    topo:
      A digraph containing all switches and links in the network
      Ingress edge nodes have their "edge_in" attribute equal to True
      Egress edge nodes have their "edge_out" attribute equal to True
      Each edge has an attribute called "c" which contains its capacity
    traffic_req:
      A dictionary from ingress egress pairs, to a tuple containing the 
      estimated traffic and state requirements.
    state_dep:
      a digraph representing state dependencies
    '''
    assert isinstance(topo, DiGraph) 
    
    m = Model('routing and state placement MIP')
    
    sw = topo.nodes()
    for x in sw:
        if not 'edge_in' in topo.node[x]:
            print x
            return 
    sw_in = [x for x in sw if topo.node[x]['edge_in'] == True]
    sw_eg = [x for x in sw if topo.node[x]['edge_out'] == True]
    sw_ie = tuplelist(itertools.product(sw_in, sw_eg))
    sw_ie = [x for x in sw_ie if x in traffic_req and traffic_req[x] > 0]
    p_sw = set(sw) - set(sw_in) - set(sw_eg) 
    edges = tuplelist(topo.edges())
    print len(edges)
    print len(sw_in), len(sw_eg)
    print 'st_req', len(st_req)
    
    st_to_flow = state_dict(st_req, sw_ie)
    need_dep = req_dep_dict(st_to_flow, state_dep)      

    incomings = {}
    outgoings = {}
    for n in sw:
        incomings[n] = edges.select('*', n)
        outgoings[n] = edges.select(n, '*')

    print 0
    t_s = time()
    R = {}
    P = {}
    for (u, v) in sw_ie:
        for (i, j) in edges:
            if i in sw_in and (not i == u):
                continue
            if j in sw_eg and (not j == v):
                continue
            R[u, v, i, j] = m.addVar(lb = 0.0, 
                                     ub = 1.0,
                                     vtype = GRB.CONTINUOUS, 
                                     name = 'R_%s_%s_%s_%s' % (u, v, i, j))
            
            if (u, v) in need_dep:
                for s in need_dep[u, v]:
                    n = Ps[s]
                    if not (n, u, v, i, j) in P:
                        P[n, u, v, i, j] = m.addVar(lb = 0.0, 
                                             ub = 1.0,
                                             vtype = GRB.CONTINUOUS, 
                                             name = 'P_%s_%s_%s_%s_%s' % (n, u, v, i, j)) 

    m.update()
    print 1, time() - t_s
    t_s = time()
    #####  Objective #####

    obj = LinExpr()
    c = []
    rs = []
    for (i, j) in edges:
        coeff = 1.0 / topo.edge[i][j]['c']
        for (u, v) in sw_ie:
            if (u, v, i, j) in R:
                c.append(coeff * traffic_req[u, v])
                rs.append(R[u, v, i, j])
                #obj += coeff * traffic_req[u, v] * R[u, v, i, j]
    obj.addTerms(c, rs) 
    m.setObjective(obj, GRB.MINIMIZE)
    print 2, time() - t_s
    t_s = time()
    ##### Constraints #####
    
    ## Flow Preserveation
    for n in sw:
        incoming = incomings[n]
        outgoing = outgoings[n]
        for (u, v) in sw_ie:
            constr = LinExpr()
            #incoming = edges.select('*', n)
            #outgoing = edges.select(n, '*')
            #constr += quicksum([traffic_req[u, v] * R[u, v, i, n] for (i, _) in incoming if (u, v, i, n) in R])
            #constr -= quicksum([traffic_req[u, v] * R[u, v, n, j] for (_, j) in outgoing if (u, v, n, j) in R])
            vars1 = [R[u, v, i, n] for (i, _) in incoming if (u, v, i, n) in R]
            cs1 = [traffic_req[u, v]] * len(vars1)
            vars2 = [R[u, v, n, j] for (_, j) in outgoing if (u, v, n, j) in R]
            cs2 = [-traffic_req[u, v]] * len(vars2)
            constr.addTerms(cs1 + cs2, vars1 + vars2)
            if n == u:
                constr += traffic_req[u, v]

            if n == v:
                constr -= traffic_req[u, v]
            m.addConstr(constr, GRB.EQUAL, 0)
    
    print 3, time() - t_s
    t_s = time()
    ## Link Capacity ##
    for (i, j) in edges:
        constr = LinExpr()
        vs = [R[u, v, i, j] for (u, v) in sw_ie if (u, v, i, j) in R]
        cs = [traffic_req[u ,v] for (u, v) in sw_ie if (u, v, i, j) in R]
        constr.addTerms(cs, vs)
        m.addConstr(constr, GRB.LESS_EQUAL, topo.edge[i][j]['c'])
        #m.addConstr(quicksum([traffic_req[u, v] * R[u, v, i, j] for (u, v) in sw_ie if (u, v, i, j) in R]), 
        #            GRB.LESS_EQUAL, topo.edge[i][j]['c'])
    
    print 4, time() - t_s
    t_s = time()
    
    ## Flows that need S should go through the node it's placed on ##
    for s in Ps:
        n = Ps[s]
        for (u, v) in st_to_flow[s]:
            
            #incoming = edges.select('*', n)
            incoming = incomings[n]
            constr = LinExpr()
            rs = [R[u, v, i, n] for (i, _) in incoming if (u, v, i, n) in R]
            cs = [1] * len(rs)
            constr.addTerms(cs, rs)
            m.addConstr(constr, GRB.GREATER_EQUAL, 1)
            #m.addConstr(quicksum([R[u, v, i, n] for (i, _) in incoming if (u, v, i, n) in R]),
            #            GRB.GREATER_EQUAL, Ps[s, n])
                     
    print 6, time() - t_s
    t_s = time()
    
    ## state flow limited to traffic flow ##
    '''for (u, v) in sw_ie:
        for (i, j) in edges:
            if i in sw_in and (not i == u):
                continue
            if j in sw_eg and (not j == v):
                continue
            
            if (u, v) in need_dep:
                for s in need_dep[u, v]:
                    m.addConstr(P[s, u, v, i, j] <= R[u, v, i, j])
    '''
    for (u, v, i, j) in R:
        for s in states:
            if (s, u, v, i, j) in P:
                 m.addConstr(P[s, u, v, i, j] <= R[u, v, i, j])
    
    print 7, time() - t_s
    t_s = time()

    ## state flow generation and preservation ##
    ## limit source of state flow ##
    
    for (u, v) in need_dep:
        for s in need_dep[u, v].keys():
            sn = Ps[s]
            for n in p_sw:
                #for s in states:
                #for n in p_sw:
                #for (u, v) in st_to_flow[s]:
                #incoming = edges.select('*', n)
                #outgoing = edges.select(n, '*')
                
                incoming = incomings[n]
                outgoing = outgoings[n]
                in_exp = LinExpr()
                out_exp = LinExpr()
                
                vars1 = [P[sn, u, v, i, n] for (i, _) in incoming if (u, v, i, n) in R]
                cs1 = [1] * len(vars1)
                vars2 = [P[sn, u, v, n, j] for (_, j) in outgoing if (u, v, n, j) in R]
                cs2 = [1] * len(vars2)
                in_exp.addTerms(cs1, vars1)
                out_exp.addTerms(cs2, vars2)
                #in_exp += quicksum([P[s, u, v, i, n] for (i, _) in incoming if (u, v, i, n) in R])
                #out_exp += quicksum([P[s, u, v, n, j] for (_, j) in outgoing if (u, v, n, j) in R])
                if sn == n:
                    in_exp += 1  
                m.addConstr(in_exp - out_exp, GRB.EQUAL, 0)
                #m.addConstr(in_exp, GRB.LESS_EQUAL, 1)
        
            #for (u, v) in st_to_flow[s]:
            #incoming = edges.select('*', v)
            incoming = incomings[v]
            in_exp = LinExpr()
            in_exp += quicksum([P[sn, u, v, i, v] for (i, _) in incoming if (u, v, i, v) in R])
            m.addConstr(in_exp, GRB.EQUAL, 1)
    
    print 8, time() - t_s
    t_s = time()

    ## state dependency ##
    for (u, v) in need_dep:
        for s1 in need_dep[u, v]:
            for s2 in need_dep[u, v][s1]:
                if s1 == s2:
                    continue
                if (s1, s2) in state_dep:
                    sn1 = Ps[s1]
                    sn2 = Ps[s2]
                    if sn1 != sn2:
                        #incoming = edges.select('*', n)
                        incoming = incomings[sn2]
                        m.addConstr(quicksum([P[sn1, u, v, i, sn2] for (i, _) in incoming if (u, v, i, sn2) in R]),
                                    GRB.GREATER_EQUAL, 1)

    print 9, time() - t_s
    t_s = time()
    optimize_mip(m)
    print 'te resovling', time() - t_s 

def optimize_mip(m):
    #m.params.Threads = 8
    m.optimize()
    if m.status == GRB.status.INFEASIBLE:
        m.computeIIS()
        m.write('m.ilp')
    '''elif m.status == GRB.status.OPTIMAL:
        f = open('ilp.out', 'w')
        for v in m.getVars():
            if v.x > 0.001:
                f.write("%s : %.2f\n" % (v.varName, v.x))
        f.close()
    '''
def load_pickle(fname):
    f = open('../eval/temp/' + fname)
    res = pickle.loads(f.read())
    f.close()
    return res


if __name__ == "__main__":
    save_list = ['graph.txt', 'traffic_req.txt', 'st_req.txt', 'states.txt', 'ilp.txt', 'dep.txt'] 
    res = [load_pickle(f) for f in save_list]
    (topo, traffic_req, st_req, states, ilp, dep) = res
    (R, PS, sw_ie, st_to_flow, p_sw) = ilp
    Ps = {}
    for s, n in PS:
        if PS[s, n] > 0.1:
            Ps[s] = n
    create_mip(topo, traffic_req, st_req, states, dep, Ps)

    
