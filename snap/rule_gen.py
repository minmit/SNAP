from snap.fdd import *

inp_fdd_fields = [('t_srcip', 32), 
                  ('t_dstip', 32),
                  ('t_ethertype', 16)]

fdd_id_length = 16
inport_length = 8
outport_length = 8
dst_length = 8
preamble_length = 64
def_length = 32
mac_length = 48
state_length = 8
sw_port_length = 16
transport_plength = 16

parsed_fields = {'inport': ( inport_length, 64),
                 'outport': (outport_length, 64 + 8),
                 'dst': (dst_length, 64 + 2 * 8),
                 'exec_node': (fdd_id_length, 64 + 3 * 8),
                 'ethertype': (16, 64 + 3 * 8 + 16 + 2 * 48),
                 'srcip': (def_length, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96),
                 'dstip': (def_length, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32),
                 # for netasm tests should be removed
                 'srcport' : (transport_plength, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32 + 32),
                 'dstport' : (transport_plength, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32 + 32 + 16),
                 'rdata' : (def_length, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32 + 32 + 2 * 16), 
                 'qname' : (def_length, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32 + 32 + 2 * 16 + 32),  
                 'dns.ttl' : (def_length, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32 + 32 + 2 * 16 + 32 + 32),  
                 'agent' : (def_length, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32 + 32 + 2 * 16 + 32 + 32 + 32),  
                 'sid' : (def_length, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32 + 32 + 2 * 16 + 4 * 32),  
                 'smtp.MTA' : (def_length, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32 + 32 + 16 + 5 * 32),  
                 'ftp.port' : (def_length, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32 + 32 + 16 + 6 * 32),  
                 'tcpflags' : (def_length, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32 + 32 + 16 + 7 * 32),  
                 'proto' : (def_length, 64 + 3 * 8 + 16 + 2 * 48 + 16 + 96 + 32 + 32 + 16 + 8 * 32),  
 
               }
ops = {
      "!=": "Op.Neq",
      "=" : "Op.Eq",  
      "+" : "Op.Add",
      "-" : "Op.Sub",
      "xor" : "Op.Xor",
      }
   
def create_table(name, size, field_type, table_type):
    insts = []
    insts.append("%s_TABLE_SIZE = Size(%d)" % (name, size))
    insts.append("decls.table_decls[TableId('%s_table')] = Table(TableFieldsCollection.%sFields(), %s_TABLE_SIZE, TableTypeCollection.%s)" % (name, field_type, name, table_type))
    insts.append("%s_table = decls.table_decls[TableId('%s_table')]" % (name, name))
    return insts
    
def add_field_to_table(table_name, field_name, field_length, match_type = None):
    insts = []
    if match_type is None:
        insts.append("%s_table.table_fields[Field('%s')] = Size(%d)" % (table_name, field_name, field_length))
    else:
        insts.append("%s_table.table_fields[Field('%s')] = Size(%d), MatchTypeCollection.%s" % (table_name, field_name, field_length, match_type))
    return insts

def get_decls(inport_fdd_fields, states, state_info):
    insts = []
    insts.append("PORT_COUNT_BITMAP = 0xFFFF")
    insts.append("decls = Decls(TableDecls())")
   
    '''# create inport fdd tables
    table_name = "inport_fdd"
    insts.extend(create_table(table_name, 100, "Match", "CAM"))
    for fname, flen in inport_fdd_fields:
        insts.extend(add_field_to_table(table_name, fname, flen, "Binary")) 
    
    table_name = "inport_exec_node"
    insts.extend(create_table(table_name, 100, "Simple", "RAM"))
    insts.extend(add_field_to_table(table_name, "in_exec_node", fdd_id_length))
    '''
    # create routing table
    table_name = "routing_match"
    insts.extend(create_table(table_name, 50, "Match", "CAM"))
    insts.extend(add_field_to_table(table_name, "t_inport", inport_length, "Binary"))
    insts.extend(add_field_to_table(table_name, "t_outport", outport_length, "Binary"))

    table_name = "routing_val"
    insts.extend(create_table(table_name, 50, "Simple", "RAM"))
    insts.extend(add_field_to_table(table_name, "tt_outport", sw_port_length))

    # creating set outport table
    table_name = "outport_match"
    insts.extend(create_table(table_name, 50, "Match", "CAM"))
    insts.extend(add_field_to_table(table_name, "o_state", state_length, "Binary"))
    insts.extend(add_field_to_table(table_name, "o_inport", inport_length, "Binary"))

    table_name = "outport_val"
    insts.extend(create_table(table_name, 50, "Simple", "RAM"))
    insts.extend(add_field_to_table(table_name, "o_outport", sw_port_length))
 
    
    # creating state tables
    for s in states:
        l = state_info[s]
        table_name = "%s_index" % s
        insts.extend(create_table(table_name, 50, "Match", "CAM"))
        for i in range(l):   
            fname = "%s_f_%d" % (s, i)
            insts.extend(add_field_to_table(table_name, fname, def_length, "Binary"))
         
        table_name = "%s_value" % s #assuming one value
        insts.extend(create_table(table_name, 50, "Simple", "RAM"))
        insts.extend(add_field_to_table(table_name, "%s_f_v" % s, def_length))
   
        table_name = "%s_meta" % s
        insts.extend(create_table(table_name, 2, "Simple", "RAM"))
        insts.extend(add_field_to_table(table_name, "%s_m" % s, def_length))

    return insts 

def add_field_to_header(fname, flen):
    insts = []
    insts.append("I.ADD(O.Field(Field('%s')), Size(%d))" % (fname, flen))
    insts.append("I.LD(O.Field(Field('%s')), O.Value(Value(0, Size(%d))))" % (fname, flen))
    return insts    

def load_field_from_packet(fname, ind):
    return ["I.LD(O.Field(Field('%s')), O.Location(Location(O.Value(Value(%d, Size(%d))))))" % (fname, ind, def_length)]

def load_field(f, src):
    return ["I.LD(%s, %s)" % (f, src)]
 
def get_fields(fields):
    insts = []
    for f in fields:
        flen, ind = fields[f]
        insts.extend(add_field_to_header(f, flen))
        insts.extend(load_field_from_packet(f, ind))
    insts.extend(add_field_to_header("index", def_length))
    insts.extend(add_field_to_header("value", def_length))
    insts.extend(add_field_to_header("state", state_length))
    return insts    

def get_sub_fdds(pol_fdd, states, acc):
    if isinstance(pol_fdd, Node):
        t = pol_fdd.test
        if isinstance(t, STest) and t.var in states:
            acc.append(pol_fdd)
        else:
            get_sub_fdds(pol_fdd.lchild, states, acc)
            get_sub_fdds(pol_fdd.rchild, states, acc)
 
    elif isinstance(pol_fdd, Leaf):
        for act_seq in pol_fdd.act_info:
            _, smods = pol_fdd.act_info[act_seq]
            keys = set(smods.keys())
            if len(states & keys) > 0:
                acc.append(pol_fdd)
                break
    else:
        raise TypeError

def field(fname):
    return "O.Field(Field('%s'))" % fname

def sfield(fname):
    return "Field('%s')" % fname

def mask(s):
    return "Mask(0x%s)" % ("F" * s)

def value(v, size):
    try:
        return "O.Value(Value(%d, Size(%d)))" % (v, size)
    except:
        print type(v), v, type(size), size
        raise TypeError

def loc(ind):
    return "O.Location(Location(O.Value(Value(%d, Size(%d)))))" % (ind, def_length)

def label(l):
    return "Label('%s')" % l

def ilabel(l):
    return ["I.LBL(%s)" % label(l)]

def branch(first, op, second, label):
    return ["I.BR(%s, %s, %s, %s)" % (first, ops[op], second, label)] 

def table(tname):
    return "TableId('%s_table')" % tname

def operands(ops, typ):
    return "O.Operands%s(%s)" % (typ, ",".join(ops))


def lookup(tname, match, ind):
    insts = ["I.LKt(%s, TableId('%s_table'), %s)" % (ind, tname, match)]
    return insts

def load(tname, dst, ind):
    insts = ["I.LDt(%s, TableId('%s_table'), %s)" % (dst, tname, ind)]
    return insts

def store(tname, val, ind):
    insts = ["I.STt(TableId('%s_table'),%s, %s)" % (tname, ind, val)]
    return insts

def jump(l):
    return ["I.JMP(Label('%s'))" % l]

def store_to_packet(src, loc):
    return ["I.ST(%s, %s)" % (loc, src)]

def set_and_store_field(fname, val, fields):
    insts = []
    insts.extend(load_field(field(fname), value(val, fields[fname][0]))) 
    insts.extend(store_to_packet(field(fname), loc(fields[fname][1])))
    return insts 

def comp(dst, first, op, second):
    insts = ["I.OP(%s, %s, %s, %s)" % (dst, first, ops[op], second)]
    return insts

def get_value(x):
    if isinstance(x, bool):
        return (1 if x else 0)
    elif isinstance(x, int):
        return x
    else:
        raise TypeError

def get_fdd_insts(fdd, fields, states, ranks, state_sw_map, 
                  state_port_map, insts, to_leaf=True):
    insts.extend(ilabel("LBL_%d" % fdd.id))
    if isinstance(fdd, Node):
        t = fdd.test
        if isinstance(t, FVTest):
            if isinstance(t.rh, IPv4Network):
                rh = t.rh._ip
            elif isinstance(t.rh, MAC):
                raise TypeError # FIXME
            elif isinstance(t.rh, int):
                rh = t.rh
            else:
                raise TypeError
            size = fields[t.lh][0] 
            insts.extend(branch(field(t.lh), "!=", value(rh, size), label("LBL_%d" % (fdd.rchild.id))))
        elif isinstance(t, FFTest):
            insts.extend(branch(field(t.lh), "!=", field(t.rh), label("LBL_%d" % (fdd.rchild.id))))
        elif isinstance(t, STest):
            s = t.var
            if s in states: 
                if to_leaf: # TODO: lots of other cases here, index not field, value being field...
                    match = [field(f) for f in t.index]
                    insts.extend(lookup("%s_index" % s, operands(match, "_"), field("index")))
                    insts.extend(branch(field("index"), "!=", value(-1, def_length), label("LBL_%d_1" % fdd.id))) 
                    insts.extend(load("%s_meta" % s, operands([field("value")], "__"), value(1, def_length)))
                    insts.extend(jump("LBL_%d_2" % fdd.id))
                    insts.extend(ilabel("LBL_%d_1" % fdd.id))
                    insts.extend(load("%s_value" % s, operands([field("value")], "__"), field("index")))
                    insts.extend(ilabel("LBL_%d_2" % fdd.id))
                    try: # TODO: this is a hack, do a longer term fix
                        rh = get_value(t.rh[0])
                        insts.extend(branch(field("value"), "!=", value(rh, def_length), label("LBL_%d" % (fdd.rchild.id))))
                    except TypeError:
                        rh = t.rh[0]
                        insts.extend(branch(field("value"), "!=", field(rh), label("LBL_%d" % (fdd.rchild.id))))
                else:
                    insts.extend(load_field(field("exec_node"), value(fdd.id, fdd_id_length))) 
                    insts.extend(jump("LBL_ST"))
                    return
            else:
                insts.extend(set_and_store_field("exec_node", fdd.id, fields)) 
                insts.extend(set_and_store_field("dst", int(state_sw_map[s]), fields))
                insts.extend(load_field(field("state"), value(ranks[s], state_length)))
                insts.extend(jump("LBL_SET_OUTPORT"))
                return
        else:
            raise TypeError

        get_fdd_insts(fdd.lchild, fields, states, ranks, state_sw_map, 
                      state_port_map, insts, to_leaf)
        get_fdd_insts(fdd.rchild, fields, states, ranks, state_sw_map, 
                      state_port_map, insts, to_leaf)

    elif isinstance(fdd, Leaf):
        # TODO: Assuming there is no parallel actions (not sure
        #       how to do that with NetASM
        act_seq = fdd.act_info.keys()[0]
        fmod, smod = fdd.act_info[act_seq]
        common_st = set(smod.keys()) & states
        for s in common_st:
            for sm in smod[s]:
                match = [field(f) for f in sm.index] #TODO: same lost of other cases here...
                insts.extend(lookup("%s_index" % sm.var, operands(match, "_"), field("index")))
                insts.extend(branch(field("index"), "!=", value(-1, def_length), label("LBL_%d_1" % fdd.id))) 
                
                # load next index
                insts.extend(load("%s_meta" % sm.var, operands([field("index")], "__"), value(0, def_length)))
                # store the match part
                match_with_mask = ["(%s, %s)" % (field(f), mask(fields[f][0] / 4)) for f in sm.index]
                insts.extend(store("%s_index" % sm.var, operands(match_with_mask, "Masks_"), field("index")))
                # figure out the value
                if isinstance(sm, SInc):
                    insts.extend(load("%s_meta" % sm.var, operands([field("value")], "__"), value(1, def_length)))
                    if sm.step > 0:
                        insts.extend(comp(field("value"), field("value"), "+", value(1, def_length)))
                elif isinstance(sm, SAction):
                    try: #TODO: This is a hack, do a better fix
                        insts.extend(load_field(field("value"), value(get_value(sm.rh[0]), def_length)))
                    except TypeError:
                        insts.extend(load_field(field("value"), field(sm.rh[0])))
                else:
                    raise TypeError
                # store the value
                insts.extend(store("%s_value" % sm.var, operands([field("value")], "_"), field("index")))
                
                # increment and store index
                insts.extend(comp(field("index"), field("index"), "+", value(1, def_length))) # TODO: assuming no overflow
                insts.extend(store("%s_meta" % sm.var, operands([field("index")], "_"), value(0, def_length))) 

                insts.extend(jump("LBL_%d_2" % fdd.id))

                # figure out the new value
                insts.extend(ilabel("LBL_%d_1" % fdd.id))
                if isinstance(sm, SInc):
                    insts.extend(load("%s_value" % sm.var, operands([field("value")], "__"), field("index")))
                    if sm.step > 0:
                        insts.extend(comp(field("value"), field("value"), "+", value(1, def_length)))
                    else:
                        insts.extend(comp(field("value"), field("value"), "-", value(1, def_length)))

                elif isinstance(sm, SAction):
                    try: #TODO: This is a hack, do a better fix
                        insts.extend(load_field(field("value"), value(get_value(sm.rh[0]), def_length)))
                    except TypeError:
                        insts.extend(load_field(field("value"), field(sm.rh[0])))

                else:
                    raise TypeError

                # store the value
                insts.extend(store("%s_value" % sm.var, operands([field("value")], "_"), field("index")))
                insts.extend(ilabel("LBL_%d_2" % fdd.id))
                        
        other_st = set(smod.keys()) - common_st 
        max_rank = max([ranks[x] for x in states]) if len(states) > 0 else -1
        other_set = [(ranks[x], x) for x in other_st if ranks[x] > max_rank]
        if len(other_set) > 0:
            next_state = min(other_set)[1]
            insts.extend(set_and_store_field("exec_node", fdd.id, fields)) 
            insts.extend(set_and_store_field("dst", int(state_sw_map[next_state]), fields))
            insts.extend(load_field(field("state"), value(ranks[next_state], state_length)))
            insts.extend(jump("LBL_SET_OUTPORT"))
        else:
            for f in fmod: 
                insts.extend(set_and_store_field(f, fmod[f], fields))
            insts.extend(jump("LBL_ROUTE"))
        
    else:
        raise TypeError

def process(pol_fdd, fdds, is_edge, inports, fields,
            states, ranks, state_sw_map, state_port_map):
    insts = []
    ids = [f.id for f in fdds]
    insts.extend(ilabel("LBL_PROCESS"))
    if is_edge:
        for x in range(len(inports)):
            i = inports[x]
            insts.extend(ilabel("LBL_INP_%d" % i))
            if x == len(inports) - 1:
                lbl = label("LBL_ST")
            else:
                lbl = label("LBL_INP_%d" % inports[x + 1]) 
            insts.extend(branch(field("inport_bitmap"), "!=", value((1 << (i - 1)), sw_port_length), lbl))
            insts.extend(jump("LBL_FDD")) 
        insts.extend(ilabel("LBL_FDD"))
        get_fdd_insts(pol_fdd, fields, states, ranks, state_sw_map,
                    state_port_map, insts, False)
    insts.extend(ilabel("LBL_ST"))
    for i in range(len(fdds)):
        fdd = fdds[i]
        if i == len(fdds) - 1:
            lbl = label("LBL_ROUTE")
        else:
            lbl = label("LBL_ST_%d" % (i + 1))
        insts.extend(ilabel("LBL_ST_%d" % i))
        insts.extend(branch(field("exec_node"), "!=", value(fdd.id, fdd_id_length), lbl))
        get_fdd_insts(fdd, fields, states, ranks, state_sw_map, state_port_map, insts, True)
        
    insts.extend(jump("LBL_ROUTE"))
    return insts

def set_outport(fields):
    insts = []
    insts.extend(ilabel("LBL_SET_OUTPORT"))
    insts.extend(lookup("outport_match", operands([field("state"), field("inport")], "_"), field("index")))
    insts.extend(branch(field("index"), "!=", value(-1, def_length), label("LBL_SET_OUTPORT_1")))
    insts.extend(set_and_store_field("outport", 0, fields))
    insts.extend(jump("LBL_ROUTE"))
    insts.extend(ilabel("LBL_SET_OUTPORT_1"))
    insts.extend(load("outport_val", operands([field("outport")], "__"), field("index")))
    #insts.extend(store_to_packet(field("outport"), loc(fields["outport"][1])))
    insts.extend(jump("LBL_ROUTE"))
    return insts

def routing():
    insts = []
    insts.extend(ilabel("LBL_ROUTE"))
    insts.extend(lookup("routing_match", operands([field("inport"), field("outport")], "_"), field("index") ))
    insts.extend(branch(field("index"), "=", value(-1, def_length), label("LBL_DRP")))
    insts.extend(load("routing_val", operands([field("outport_bitmap")], "__"), field("index")))
    insts.extend(jump("LBL_HALT"))
    insts.extend(ilabel("LBL_DRP")) 
    insts.extend(["I.DRP()"])
    return insts

def code(n, pol_fdd, is_edge, inports, fields,
            states, ranks, state_sw_map, state_port_map):
    insts = []
    insts.extend(branch(field("ethertype"), "=", value(0x0800, fields["ethertype"][0]), label("LBL_CODE")))
    insts.extend(comp(field("outport_bitmap"), field("inport_bitmap"), "xor", value(0xFFFF, 16)))
    insts.extend(jump("LBL_HALT"))
    insts.extend(ilabel("LBL_CODE"))
    insts.extend(branch(field("dst"), "!=", value(n, fields['dst'][0]), label("LBL_ROUTE")))
    fdds = []
    get_sub_fdds(pol_fdd, states, fdds)
    insts.extend(process(pol_fdd, fdds, is_edge, inports, fields,
                         states, ranks, state_sw_map, state_port_map))
    insts.extend(set_outport(fields))
    insts.extend(routing())
    insts.extend(ilabel("LBL_HALT"))
    insts.append("I.HLT()")
    return insts

def routing_table_com(sw, port_map, R):
    rules = []
    prefix = "add-table-entry sw%d routing_" % sw
    ind = 0
    mask = "0x%s" % ("F" * (inport_length / 4))
    sw = str(sw)
    for (u, v, i, j) in R:
        if i == sw and R[u, v, i, j] > 0.00001: # TODO: Assuming single path
            u = u[1:]
            v = v[1:]
            rule = "match_table %d {'t_inport':(%s,%s),'t_outport':(%s,%s)}" % (ind, u, mask, v, mask)
            rules.append(prefix + rule)
            port = port_map[sw][j]
            rule = "val_table %d {'tt_outport':%d}" % (ind, 1 << (port - 1))
            rules.append(prefix + rule)
            ind += 1
    return rules

def set_outport_com(sw, state_port, ranks):
    rules = []
    prefix = "add-table-entry sw%d outport_" % sw 
    ind = 0
    mask = "0x%s" % ("F" * (inport_length / 4))
    
    for s in state_port:
        for u in state_port[s]:
            rule = "match_table %d {'o_state':(%d,%s),'o_inport':(%s,%s)}" % (ind, ranks[s], mask, u, mask)
            rules.append(prefix + rule)
            vs = [int(x) for x in state_port[s][u]]
            rule = "val_table %d {'o_outport':%d}" % (ind, min(vs))
            rules.append(prefix + rule)
            ind += 1
    return rules

def state_meta_com(sw, states):
    rules = []
    rule = "add-table-entry sw%d %s_meta_table %d {'%s_m':%d}" 
    for s in states:
        rules.append(rule % (sw, s, 0, s, 0))
        rules.append(rule % (sw, s, 1, s, 0))
    return rules

def generate_dataplane(n, pol_fdd, inports, states, ranks, state_sw_map,
                        state_port_map, is_edge, port_map, R, 
                        dfile, cfile):
    """
    """
    # TODO: commands for two tables, routing and set_outport, and meta table for states
    n = int(n)
    state_info = {}
    get_state_info(pol_fdd, state_info)
    template = """
from netasm.netasm.core import *
def main():
    %s;
    code = I.Code(Fields(), I.Instructions(%s, I.ATM(I.Code(Fields(%s), I.Instructions(*[%s]))), I.HLT()));return Policy(decls, code)
""" 
    dataplane_str = template % (";".join(get_decls(parsed_fields, states, state_info)),
                                ",".join(get_fields(parsed_fields)),
                                ",".join([sfield(f) for f in (parsed_fields.keys() + ["index", "value", "state"])]),
                                ",\n".join(code(n, pol_fdd, is_edge, inports, parsed_fields,
                                              states, ranks, state_sw_map, state_port_map)))
                                
    f = open(dfile, 'w')
    f.write(dataplane_str)
    f.close()

    coms = []
    coms.extend(routing_table_com(n, port_map, R))
    coms.extend(set_outport_com(n, state_port_map, ranks))
    coms.extend(state_meta_com(n, states))
    coms_str = "\n".join(coms)
    
    f = open(cfile, 'w')
    f.write(coms_str)
    f.close()
