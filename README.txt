LLB - the low-level load balancer


LLB aims at being the load-balancing tier that takes incomming connections from customers and forwards them to a set of machines that registered their interest in receiving these incoming packets.

It's made up of two components - one that sits at the control plane, and another, at the data plane:

1.      A classifier stays in the hot path (traffic control), performing the necessary packet mangling; and
2.      A Golang Daemon that controls the map of backends that the classifier should send traffic to.

The daemon continuosly gather information about the list of backends from a given provider and makes sure that traffic is sent to them only when they're healthy.


        while 1:
                backends := provider.gather_backends()
                for backend := range backends:
                        llb.register_backend(backend)


Whenever a new backend is meant to be registered, deregistered or marked (un)healthy, a map (that is shared between the daemon and the classifier) is updated.

At a high level, LLB takes the job of deciding to which machines packets should be forwarded when they come.


        (public)                        (private)


    connection
        |                     .--\  \---> (x) cluster1-lb       (unhealthy)
        |                     |
        *----> llb -----------+---------> cluster2-lb           (healthy)
         Who should take      |
         this connection?     *---------> cluster3-lb           (healthy)


Operating at kernel space, the data plane performs zero connections, acting more like a router that is aware of connections.

Having all the traffic passing through it, two tables are maintained: DNAT and SNAT.

These tables have updates and lookups hapenning at both directions. For instance, at the ingress path (when the traffic is coming from the outside to the inside of the network):


        INGRESS: !is_from_backend_cidr(pkt->saddr)


                (public)                 (private)

        1.1.1.1        2.2.2.2     10.0.0.1     10.0.0.2
        connection ----------> llb --------------> machine1



And at the egress path (when packets are coming from our cluster and going to the outside world).


        EGRESS: is_from_backend_cidr(pkt->saddr)


                (public)                 (private)

        1.1.1.1        2.2.2.2     10.0.0.1     10.0.0.2
        connection <---------- llb <-------------- machine1


During INGRESS (public to private), to have the packets sent to an internal machine (private), we direct the packet by rewriting its destination address to the private machine, but given that the server is meant to generate packets back to us (and not 1.1.1.1), we need to update its source address as well (the private one) and keep track of that:


        incoming_pkt = {source: {1.1.1.1,  eph1}, dest: {2.2.2.2,  80}}
        existing_pkt = map_lookup(dnat_table, incoming_pkt)
        if (existing_pkt) {
                return
        }

        new_pkt = clone(incoming_pkt)
        new_pkt.dest.addr = 10.0.0.2
        new_pkt.source.addr = 10.0.0.1

        map_update(dnat_table,
                incoming_pkt,
                new_pkt)
        map_update(snat_table,
                {source: new_pkt.dst, dest: new_pkt.source},
                {source: incoming_pkt.dst, dest: incoming_pkt.source})
        ACCEPT


During egress though, we have to perform the opposite: rewrite source and destination so that the source is our load-balancer (public) and the destination is the client (public).


        outgoing_pkt = {source: {10.0.0.2, 80}, dest: {10.0.0.1, eph1}}
        new_pkt = map_lookup(dnat_table, {src: outgoing_pkt.dest, dest: outgoing_pkt.src})
        if (!new_pkt)
                DROP
        ACCEPT


Given that the table can grow forever, from time to time we need to remove the connections that have been terminated.
