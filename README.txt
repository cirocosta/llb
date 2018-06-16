llb - the low-level load balancer

llb aims at being the load-balancing tear that takes incomming connections from customers and forwards them to a set of machines that registered their interest in receiving these incoming packets.

It continuosly gather information about the list of backends from a given provider and makes sure that traffic is sent to them only when they're healthy.



        while 1:
                backends := provider.gather_backends()
                for backend := range backends:
                        llb.register_backend(backend)



At a high level, it takes the job of deciding to which machines packets should be forwarded when they come.



        (public)                        (private)


    connection
        |                     .--\  \---> (x) cluster1-lb       (unhealthy)
        |                     |
        *----> llb -----------+---------> cluster2-lb           (healthy)
         Who should take      |
         this connection?     *---------> cluster3-lb           (healthy)



Operating at kernel space, the data plane performs zero connections, acting more like a router that is aware of connections.

