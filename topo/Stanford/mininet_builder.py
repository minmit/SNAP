#!/usr/bin/env python

'''
    Copyright (C) 2012  Stanford University

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    Description: Load topology in Mininet
    Author: James Hongyi Zeng (hyzeng_at_stanford.edu)
'''

from mininet.topo import Topo

from networkx import Graph

class StanfordTopo( Topo ):
    "Topology for Stanford backbone"

    PORT_ID_MULTIPLIER = 1
    INTERMEDIATE_PORT_TYPE_CONST = 1
    OUTPUT_PORT_TYPE_CONST = 2
    PORT_TYPE_MULTIPLIER = 10000
    SWITCH_ID_MULTIPLIER = 100000
    
    DUMMY_SWITCH_BASE = 1000
    
    PORT_MAP_FILENAME = "data/port_map.txt"
    TOPO_FILENAME = "data/backbone_topology.tf"
    
    dummy_switches = set()

    def __init__( self ):
        # Read topology info
        ports = self.load_ports(self.PORT_MAP_FILENAME)        
        links = self.load_topology(self.TOPO_FILENAME)
        switches = ports.keys()

        # Add default members to class.
        super( StanfordTopo, self ).__init__()

        # Create switch nodes
        for s in switches:
            self.addSwitch( "s%s" % s )

        # Wire up switches       
        self.create_links(links, ports)
        
        # Wire up hosts
        host_id = len(switches) + 1
        for s in switches:
            # Edge ports
            for port in ports[s]:
                self.addHost( "h%s" % host_id )
                self.addLink( "h%s" % host_id, "s%s" % s, 0, port )
                host_id += 1

        # Consider all switches and hosts 'on'
        # self.enable_all()
            
    def load_ports(self, filename):
        ports = {}
        f = open(filename, 'r')
        for line in f:
            if not line.startswith("$") and line != "":
                tokens = line.strip().split(":")
                port_flat = int(tokens[1])
                
                dpid = port_flat / self.SWITCH_ID_MULTIPLIER
                port = port_flat % self.PORT_TYPE_MULTIPLIER
                
                if dpid not in ports.keys():
                    ports[dpid] = set()
                if port not in ports[dpid]:
                    ports[dpid].add(port)             
        f.close()
        return ports
        
    def load_topology(self, filename):
        links = set()
        f = open(filename, 'r')
        for line in f:
            if line.startswith("link"):
                tokens = line.split('$')
                src_port_flat = int(tokens[1].strip('[]').split(', ')[0])
                dst_port_flat = int(tokens[7].strip('[]').split(', ')[0])
                links.add((src_port_flat, dst_port_flat))
        f.close()
        return links
        
    def create_links(self, links, ports):  
        '''Generate dummy switches
           For example, interface A1 connects to B1 and C1 at the same time. Since
           Mininet uses veth, which supports point to point communication only,
           we need to manually create dummy switches

        @param links link info from the file
        @param ports port info from the file
        ''' 
        # First pass, find special ports with more than 1 peer port
        first_pass = {}
        for (src_port_flat, dst_port_flat) in links:
            src_dpid = src_port_flat / self.SWITCH_ID_MULTIPLIER
            dst_dpid = dst_port_flat / self.SWITCH_ID_MULTIPLIER
            src_port = src_port_flat % self.PORT_TYPE_MULTIPLIER
            dst_port = dst_port_flat % self.PORT_TYPE_MULTIPLIER
            
            if (src_dpid, src_port) not in first_pass.keys():
                first_pass[(src_dpid, src_port)] = set()
            first_pass[(src_dpid, src_port)].add((dst_dpid, dst_port))
            if (dst_dpid, dst_port) not in first_pass.keys():
                first_pass[(dst_dpid, dst_port)] = set()
            first_pass[(dst_dpid, dst_port)].add((src_dpid, src_port))
            
        # Second pass, create new links for those special ports
        dummy_switch_id = self.DUMMY_SWITCH_BASE
        for (dpid, port) in first_pass.keys():
            # Special ports!
            if(len(first_pass[(dpid,port)])>1):
                self.addSwitch( "s%s" % dummy_switch_id )
                self.dummy_switches.add(dummy_switch_id)
            
                self.addLink( node1="s%s" % dpid, node2="s%s" % dummy_switch_id, port1=port, port2=1 )
                dummy_switch_port = 2
                for (dst_dpid, dst_port) in first_pass[(dpid,port)]:
                    first_pass[(dst_dpid, dst_port)].discard((dpid,port))
                    self.addLink( node1="s%s" % dummy_switch_id, node2="s%s" % dst_dpid, port1=dummy_switch_port, port2=dst_port)
                    ports[dst_dpid].discard(dst_port)
                    dummy_switch_port += 1
                dummy_switch_id += 1  
                first_pass[(dpid,port)] = set()    
            ports[dpid].discard(port)
        
        # Third pass, create the remaining links
        for (dpid, port) in first_pass.keys():
            for (dst_dpid, dst_port) in first_pass[(dpid,port)]:
                self.addLink( node1="s%s" % dpid, node2="s%s" % dst_dpid, port1=port, port2=dst_port )
                ports[dst_dpid].discard(dst_port)     
            ports[dpid].discard(port)          
        

    
def get_stanford_graph():
    topo = StanfordTopo()
    graph = Graph()
    sw_cnt = 1
    sw_map = {}
    
    port_cnt = 1
    port_map = {}
    
    for n in topo.nodes():
        if not 'h' in n:
            sw_map[n] = sw_cnt
            graph.add_node(sw_cnt)
            sw_cnt += 1
    
    for (i, j) in topo.links():
        if i in sw_map and j in sw_map:
            i = sw_map[i]
            j = sw_map[j]
            graph.add_edge(i, j, c = 10000)
        elif i in sw_map:
            i = sw_map[i]
            if not i in port_map:
                port_map[i] = []
            port_map[i].append(port_cnt)
            port_cnt += 1
        elif j in sw_map:
            j = sw_map[j]
            if not j in port_map:
                port_map[j] = []
            port_map[j].append(port_cnt)
            port_cnt += 1
        
    return (graph, port_map)

if __name__ == "__main__":
    (g, pmap) = get_stanford_graph()
    f = open('topo.txt', 'w')
    f.write('edges\n')
    for n in pmap:
        f.write('%d %d\n' % (n, len(pmap[n])))
    f.write('links\n')
    for (i, j) in g.edges():
        f.write('%d %d 10000\n' % (i, j))

    f.close()
