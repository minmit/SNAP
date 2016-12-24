from snap.lang import *

threshold = 5
flow_index_src = ['srcip', 'dstip', 'srcport', 'dstport', 'proto']
flow_index_dst = ['dstip', 'srcip', 'dstport', 'srcport', 'proto']

def get_route_and_assump_policy(ports):
    routing = None
    assumptions = None
    for port in ports:
        route_part = (match(dstip = ("10.0.0.%d" % port)) >> modify(outport = port))
        if routing is None:
            routing = route_part
        else:
            routing += route_part
        assum_part = (match(srcip = ("10.0.0.%d" % port)) >> match(inport = port))
        if assumptions is None:
            assumptions = assum_part
        else:
            assumptions += assum_part
    return (routing, assumptions)

def get_sidejack_policy(ports, departmental=True):
    pol = if_(match(sid = 0),
                     identity,
                     if_(matchState('active_session', ['sid'], [False]),
                         setState('active_session', ['sid'], [True]) >> setState('client_ip', ['sid'], ['srcip']) >> setState('user_agent', ['sid'], ['agent']),
                         matchState('client_ip', ['sid'], ['srcip']) & matchState('user_agent', ['sid'], ['agent'])
                     )
                  )
    if departmental:
        webserver = '10.0.0.%d' % ports[-1]
        pol = if_(match(dstip = webserver), pol, identity)

    return pol
    
def get_dns_tunnel_policy(ports, departmental=True):
    
    type_dict['rdata'] = IPv4Network
    
    match1 = match(srcport = 53) & matchState('orphan', ['dstip', 'rdata'], [False])
    match2 = matchState('orphan', ['srcip', 'dstip'], [True])

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print cs
        match1 = match1 & match(dstip = cs)
        match2 = match2 & match(srcip = cs)

    #match(dstip = cs) & match(srcport = 53)
    pol_pred = match1
    t_branch = (setState('orphan', ['dstip', 'rdata'], [True]) >> Increment('susp', ['dstip'], 1) >>
                if_(matchState('susp', ['dstip'], [5]), setState('blacklist', ['dstip'], [True]), identity)
                )
    #match(srcip = cs) & matchState('orphan', ['srcip', 'dstip'], [True])
    f_branch = if_(match2, 
                    setState('orphan', ['srcip', 'dstip'], [False]) >> Increment('susp', ['srcip'], -1))

    pol = if_(pol_pred, t_branch, f_branch)
    
    return pol
 
def get_dns_tunnel_multi(ports, cnt, departmental=True):
    type_dict['rdata'] = IPv4Network
    pol = None
    for i in range(0, cnt):
        ind = (i % len(ports)) + 1
        cs = '10.0.0.%d' % ports[-ind] 
        orphan = 'orphan%d' % i
        susp = 'susp%d' % i
        blacklist = 'blacklist%d' % i
        pol_pred = match(dstip = cs) & match(srcport = 53)
        t_branch = (setState(orphan, ['dstip', 'rdata'], [True]) >> Increment(susp, ['dstip'], 1) >>
                    if_(matchState(susp, ['dstip'], [5]), setState(blacklist, ['dstip'], [True]), identity)
                    )
        f_branch = if_(match(srcip = cs) & matchState(orphan, ['srcip', 'dstip'], [True]), 
                        setState(orphan, ['srcip', 'dstip'], [False]) >> Increment(susp, ['srcip'], -1))

        pol_part = if_(pol_pred, t_branch, f_branch)

        if pol is None:
            pol = pol_part
        else:
            pol += pol_part
    
    return pol
 
def get_dns_tunnel_simplified_policy(ports, departmental=True):
    type_dict['ethertype'] = int
    cs = '10.0.0.%d' % ports[-1] 
    print "CS Department chosen port:", cs
    pol_pred = match(dstip = cs) & matchState('orphan', ['dstip', 'srcip'], [False])
    t_branch = (setState('orphan', ['dstip', 'srcip'], [True]) >> Increment('susp', ['dstip'], 1) >>
                if_(matchState('susp', ['dstip'], [5]), setState('blacklist', ['dstip'], [True]) >> drop, identity)
                )
    f_branch = if_(match(srcip = cs) & matchState('orphan', ['srcip', 'dstip'], [True]), 
                    setState('orphan', ['srcip', 'dstip'], [False]) >> Increment('susp', ['srcip'], -1))
    
    #t_branch = identity
    #f_branch = drop
    pol = if_(pol_pred, t_branch, f_branch)
    
    return pol

def get_stateful_firewall_policy(ports, departmental=True):   
    cs = '10.0.0.%d' % ports[-1] 
    print "CS Department chosen port:", cs
    pol_pred = match(dstip = cs)
    t_branch = matchState('conn', ['srcip', 'dstip'], [True]) 
    f_branch = if_(match(srcip = cs), setState('conn', ['dstip', 'srcip'], [True]), identity) 
    #t_branch = identity
    #f_branch = drop
    pol = if_(pol_pred, t_branch, f_branch)
    
    return pol
 
def get_domains_per_ip_policy(ports, departmental=True):
    pol_pred = match(srcport = 53)
    t_branch = if_(matchState('domain_ip', ['rdata', 'qname'], [False]),
                   Increment('domain_cnt', ['rdata'], 1) >> setState('domain_ip', ['rdata', 'qname'], [True])
                   >> if_(matchState('domain_cnt', ['rdata'], [threshold]), 
                          setState('many_domains', ['rdata'], [True]),
                              identity),
                   identity)
    f_branch = identity

    pol = if_(pol_pred, t_branch, f_branch)

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs), pol, identity)

    return pol
 
def get_ips_per_domain_policy(ports, departmental=True):   
    pol_pred = match(srcport = 53)
    t_branch = if_(matchState('ip_domain', ['qname', 'rdata'], [False]),
                   Increment('ip_cnt', ['qname'], 1) >> setState('ip_domain', ['qname', 'rdata'], [True])
                   >> if_(matchState('ip_cnt', ['qname'], [threshold]), 
                          setState('many_ips', ['qname'], [True]),
                              identity),
                   identity)
    f_branch = identity

    pol = if_(pol_pred, t_branch, f_branch)

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs), pol, identity)

    return pol 

def get_dns_ttl_change_policy(ports, departmental=True):
    pol_pred = match(srcport = 53)
    t_branch = if_(matchState('seen', ['rdata'], [False]),
                   setState('seen', ['rdata'], [True]) >> setState('last_ttl', ['rdata'], ['dns.ttl'])
                    >> setState('ttl_change', ['rdata'], [0]),
                   if_(matchState('last_ttl', ['rdata'], ['dns.ttl']),
                       identity,
                       setState('last_ttl', ['rdata'], ['dns.ttl']) >> Increment('ttl_change', ['rdata'], 1) >>
                       if_(matchState('ttl_change', ['rdata'], [threshold]),
                           setState('many_ttl_change', ['rdata'], [True]),
                            identity)
                    )
                )
    f_branch = identity

    pol = if_(pol_pred, t_branch, f_branch)

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs), pol, identity)

    return pol 

def get_spam_detection_policy(ports, departmental=True):
    UNKNOWN = 0
    TRACKED = 1
    SPAMMER = 2

    pol1 = if_(matchState('MTA_dir', ['smtp.MTA'], [UNKNOWN]),
               setState('MTA_dir', ['smtp.MTA'], [TRACKED]) >>
               setState('mail_counter', ['smtp.MTA'], [0]),
               identity)

    pol2 = if_(matchState('MTA_dir', ['smtp.MTA'], [TRACKED]),
               Increment('mail_counter', ['smtp.MTA'], 1) >>
               if_(matchState('mail_counter', ['smtp.MTA'], [threshold]),
                   setState('MTA_dir', ['smtp.MTA'], [SPAMMER]),
                   identity),
               identity)  

    pol = pol1 >> pol2 
    if departmental:
        server = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", server
        pol = if_(match(srcip = server), pol, identity)

    return pol 

def get_ftp_monitoring_policy(ports, departmental=True):   
    match1 = match(dstport = 21)
    match2 = match(srcport = 20)
       
    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        match1 = match1 & match(srcip = cs)
        match2 = match2 & match(dstip = cs)
 
    pol_pred = match1
    t_branch = setState('ftp_data_chan', ['srcip', 'dstip', 'ftp.port'], [True]) 
    f_branch = if_(match2, matchState('ftp_data_chan', ['dstip', 'srcip', 'ftp.port'], [True]), identity) 
    #t_branch = identity
    #f_branch = drop
    pol = if_(pol_pred, t_branch, f_branch)

    return pol 


def get_super_spreader_detection_policy(ports, departmental=True):
    SYN = 0
    FYN = 1
    
    pol = if_(match(tcpflags = SYN),
              Increment("spread", ['srcip'], 1) >>
              if_(matchState("spread", ['srcip'], [threshold]), 
                  setState('super_spreader', ['srcip'], [True]),
                  identity),
              if_(match(tcpflags = FYN),
                  Increment('spread', ['srcip'], -1),
                  identity) 
             ) 

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs), pol, identity)

    return pol 

def get_flow_size_policy(ports, departmental=True):
    SMALL = 0
    MEDIUM = 1
    LARGE = 2

    pol = (Increment('flow_size', flow_index_src, 1) >>
           if_(matchState('flow_size', flow_index_src, [1]),
               setState('flow_type', flow_index_src, [SMALL]),
               if_(matchState('flow_size', flow_index_src, [100]),
                   setState('flow_type', flow_index_src, [MEDIUM]),
                   if_(matchState('flow_size', flow_index_src, [1000]),
                       setState('flow_type', flow_index_src, [LARGE]),
                       identity
            )))
          )

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs) | match(srcip = cs), pol, identity)

    return pol 

def get_sample_small_policy(ports, departmental=True):
    sample_rate = 5
    pol = (Increment('small_sampler', flow_index_src, 1) >>
          if_(matchState('small_sampler', flow_index_src, [sample_rate]),
              setState('small_sampler', flow_index_src, [0]),
              drop))

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs) | match(srcip = cs), pol, identity)

    return pol 

def get_sample_med_policy(ports, departmental=True):
    sample_rate = 50
    pol = (Increment('medium_sampler', flow_index_src, 1) >>
          if_(matchState('medium_sampler', flow_index_src, [sample_rate]),
              setState('medium_sampler', flow_index_src, [0]),
              drop))

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs) | match(srcip = cs), pol, identity)

    return pol 

def get_sample_large_policy(ports, departmental=True):
    sample_rate = 500
    pol = (Increment('large_sampler', flow_index_src, 1) >>
          if_(matchState('large_sampler', flow_index_src, [sample_rate]),
              setState('large_sampler', flow_index_src, [0]),
              drop))

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs) | match(srcip = cs), pol, identity)

    return pol 

def get_size_based_sampling_policy(ports, departmental=True):
    SMALL = 0
    MEDIUM = 1
    LARGE = 2

    pol = (get_flow_size_policy(ports, departmental) >>
           if_(matchState("flow_type", flow_index_src, [SMALL]),
               get_sample_small_policy(ports, departmental),
               if_(matchState("flow_type", flow_index_src, [MEDIUM]),
                   get_sample_med_policy(ports, departmental),
                   get_sample_large_policy(ports, departmental)
            ))
          )

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs) | match(srcip = cs), pol, identity)

    return pol 

def get_selective_mpeg_policy(ports, departmental=True):
    IFRAME = 0
    pol = if_(match(frametype = IFRAME),
              setState('dep_count', ['srcip', 'dstip', 'srcport', 'dstport'], [14]),
              if_(matchState('dep_count', ['srcip', 'dstip', 'srcport', 'dstport'], [0]),
                  drop,
                  Increment('dep_count', ['srcip', 'dstip', 'srcport', 'dstport'], -1)))

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs) | match(srcip = cs), pol, identity)

    return pol 
 
def get_dns_amplification_policy(ports, departmental=True):
    match1 = match(dstport = 53)
    match2 = match(srcport = 53) & matchState('benign_req', ['dstip', 'srcip'], [False])

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        match1 = match1 & match(srcip = cs)
        match2 = match2 & match(dstip = cs)
    
    pol = if_(match1, setState('benign_req', ['srcip', 'dstip'], [True]), ~match2)

    return pol


def get_udp_flood_detection_policy(ports, departmental=True):
    UDP = 0
    pol = if_(match(proto = UDP) & matchState('udp_flooder', ['srcip'], [False]),
              Increment('udp_counter', ['srcip'], 1) >>
              if_(matchState('udp_counter', ['srcip'], [threshold]),
                  setState('udp_flooder', ['srcip'], [True]) >> drop,
                  identity),
              identity)

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs) | match(srcip = cs), pol, identity)

    return pol 

def get_heavy_hitter_policy(ports, departmental=True):
    SYN = 0
    pol = if_(match(tcpflags = SYN) & matchState('heavy_hitter', ['srcip'], [False]),
              Increment('hh_counter', ['srcip'], 1) >>
              if_(matchState('hh_counter', ['srcip'], [threshold]),
                  setState('heavy_hitter', ['srcip'], [True]),
                  identity),
              identity)

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs) | match(srcip = cs), pol, identity)

    return pol

def get_tcp_state_machine_policy(ports, departmental=True):
    SYN = 0
    FIN = 1
    SYN_ACK = 2
    ACK = 3
    FIN_ACK = 4
    RST = 5

    SYN_SENT = [0]
    SYN_RECEIVED = [1]
    ESTABLISHED = [2]
    FIN_WAIT = [3]
    FIN_WAIT2 = [4]
    CLOSED = [5]
    
    pol = if_(match(tcpflags = SYN) & matchState('tcp_state', flow_index_src, CLOSED),
              setState('tcp_state', flow_index_src, SYN_SENT),
              if_(match(tcpflags = SYN_ACK) & matchState('tcp_state', flow_index_dst, SYN_SENT),
              setState('tcp_state', flow_index_dst, SYN_RECEIVED),
              if_(match(tcpflags = ACK) & matchState('tcp_state', flow_index_src, SYN_RECEIVED),
              setState('tcp_state', flow_index_src, ESTABLISHED),
              if_(match(tcpflags = FIN) & matchState('tcp_state', flow_index_src, ESTABLISHED),
              setState('tcp_state', flow_index_src, FIN_WAIT),
              if_(match(tcpflags = FIN_ACK) & matchState('tcp_state', flow_index_dst, FIN_WAIT),
              setState('tcp_state', flow_index_dst, FIN_WAIT2),
              if_(match(tcpflags = ACK) & matchState('tcp_state', flow_index_src, FIN_WAIT2),
              setState('tcp_state', flow_index_src, CLOSED),
              if_(match(tcpflags = RST) & matchState('tcp_state', flow_index_dst, ESTABLISHED),
              setState('tcp_state', flow_index_dst, CLOSED),
              setState('tcp_state', flow_index_src, ESTABLISHED) >> setState('tcp_dst', flow_index_dst, ESTABLISHED)
      ))))))) 

    if departmental:
        cs = '10.0.0.%d' % ports[-1] 
        print "CS Department chosen port:", cs
        pol = if_(match(dstip = cs) | match(srcip = cs), pol, identity)

    return pol
     


def get_snort_policy(ports, departmental=True):
    TCP = 1
    KINDLE = 0

    cs = '10.0.0.%d' % ports[-1] 
    print "CS Department chosen port:", cs

    match1 = match(srcip = cs) & match(dstport = 80) & \
             match(apptype = KINDLE) & match(proto = TCP)

    pol = if_(match1, setState('kindle', flow_index_src, [True]), identity)

    return pol 
