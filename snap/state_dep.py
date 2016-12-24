from snap.lang import *
from snap.util import profile

def st_graph(pol):
    '''
    creates the dependency graph when
    given a policy.
    '''

    typ = type(pol)
   
    # In a >> b, all the state variables of 
    # state modifications in b get dependent
    # on state variables of state tests in a. 
    if typ == sequential:
        p = pol.policies[0]
        (smatch, smod, sgraph) = st_graph(p)
        for p in pol.policies[1:]:
            (p_smatch, p_smod, p_sgraph) = st_graph(p)
            sgraph |= p_sgraph
            sgraph |= set_product(smatch, p_smod)
            smatch |= p_smatch
            smod |= p_smod
        return (smatch, smod, sgraph)

    # In if a then p else q, all state variables of
    # state modifications in p and q get dependent 
    # on state variables of state tests in a
    elif typ == if_:
        (a_smatch, a_smod, _) = st_graph(pol.pred)
        (p_smatch, p_smod, p_sgraph) = st_graph(pol.t_branch)
        (q_smatch, q_smod, q_sgraph) = st_graph(pol.f_branch)

        smatch = a_smatch | p_smatch | q_smatch
        smod = a_smod | p_smod | q_smod
        
        # computing dependency graph.
        #note that predicates dep graph is empty
        sgraph = p_sgraph | q_sgraph        
        # we also make state variables of state tests in
        # p and q dependent on a for a more efficient order
        # in the FDD
        sgraph |= set_product(a_smatch, p_smatch | p_smod
                                        |q_smatch | q_smod) 
        return (smatch, smod, sgraph)

    # The rest of the cases do not introduce dependencies,
    # we just need to compute the state variables in state 
    # tests and state variables in state modifications
    elif issubclass(typ, parallel) or typ == intersection:
        
        def union_res(acc, x):
            (x1, x2, x3) = x
            (acc1, acc2, acc3) = acc
            acc1 |= x1
            acc2 |= x2
            acc3 |= x3
            return (acc1, acc2, acc3)

        return reduce(union_res, [st_graph(x) for x in pol.policies])

    elif typ == negate:
        return st_graph(pol.policies[0])

    elif (pol == identity or pol == drop or
          typ == match or typ == modify):
        return (set(), set(), set())

    elif typ == matchState:
        return (set([pol.state_var]), set(), set())

    elif typ == setState:
        return (set(), set([pol.state_var]), set())
    elif typ == Increment:
        return (set(), set([pol.state_var]), set())
    else:
        raise TypeError

def scc(node, adj, index, low_link, stack):
    '''
    computes the strongly connected components 
    of a directed graph
    '''

    stack.append(node)
    index[node] = max(index.values()) + 1 if len(index) > 0 else 0
    low_link[node] = index[node]
    
    comps = set()

    for nei in adj[node]:
        if not nei in index:
            n_comps = scc(nei, adj, index, low_link, stack)
            comps |= n_comps
            low_link[node] = min(low_link[node], low_link[nei])
        elif nei in stack:
            low_link[node] = min(low_link[node], index[nei]) #can also do low_link[nei]
    
    if low_link[node] == index[node]:
        res = set()
        while stack[-1] != node:
            res.add(stack.pop())
        res.add(stack.pop())
        res = frozenset(res)
        comps.add(res)
    return comps

def st_dag(V, E):
    '''
    given a directed graph, returns the
    DAG induced by the graph's
    strongly connected components and
    '''
 
    adj = dict([(v, set()) for v in V])

    for (v1, v2) in E:
        adj[v1].add(v2)
    
    sup_node = {}
    cur_sup = 0

    index = {}
    low_link = {}
    stack = []

    comps = set()
    for v in V:
        if not v in index:
            rcomps = scc(v, adj, index, low_link, stack)
            comps |= rcomps

    comp_map = {}
    for c in comps:
        for v in c:
            comp_map[v] = c

    comp_adj = {}
    for c  in comps:
        if not c in comp_adj:
            comp_adj[c] = set()
        for v in c:
            for a in adj[v]:
                if not a in c:
                    comp_adj[c].add(comp_map[a])
    
    return (comps, comp_adj)

def set_product(s1, s2):
    '''
    Cross products of two sets,
    removing pairs with the same 
    elements
    '''
    res = set()
    for e1 in s1:
        for e2 in s2:
            if e1 != e2:
                res.add((e1, e2))
    return res

def topo_order(V, E):
    ''' 
    returns a topological order
    on the nodes of a DAG
    '''
    
    ingoing = dict([(v, set()) for v in V])
    for v1 in E:
        for v2 in E[v1]:
            ingoing[v2].add(v1)

    roots = filter(lambda x : len(ingoing[x]) == 0, V)
    index = 0
    rank = {}

    while len(roots) > 0:
        r = roots[0]
        roots = roots[1:]
        rank[r] = index
        index += 1
        for nei in E[r]:
            ingoing[nei].remove(r)
            if len(ingoing[nei]) == 0:
                roots.append(nei)
    
    return rank



@profile
def st_dep(pol):
    (smatch, smod, E) = st_graph(pol)
    V = smatch | smod
    (comps, comp_adj) = st_dag(V, E)

    def eq_pairs(l):
        if len(l) < 2:
            return set()
        if len(l) == 2:
            return set([(l[0], l[1])])

        return set(zip(l, l[1:] + l[:1]))

    tied = set()
    for c in comps:
        tied |= eq_pairs(list(c))
    
    dep = set()
    for c1 in comp_adj:
        for c2 in comp_adj[c1]:
            dep |= set_product(c1, c2)

    rank = topo_order(comps, comp_adj)
    rank = sorted(rank.items(), key=lambda x : x[1])
    index = 0
    final_rank = {}
    for (c, _) in rank:
        for v in c:
            final_rank[v] = index
            index += 1
    
    return (tied, dep, final_rank)

