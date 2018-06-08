llb - the low-level load balancer

llb aims at being the load-balancing tear that takes incomming connections from customers and forward them to docker swarm clusters that should be responsible for handling such connections.

At a high level, it takes the job of deciding two which cluster load-balancer to forward traffic to based on who should handle such connection.


    connection 
        |                     .---> cluster1-lb
        |                     |
        *----> llb -----------+---> cluster2-lb
         Who should take      | 
         this connection?     *---> cluster3-lb


To make such decision, `llb` gathers the following information:

- who should respond to l7 requests to a specific domain; and
- who should answer to l4 connections to a specific port.

Not having to deal with certificates at all, `llb` decides on domains at the L7 level by performing a very early parsing of TCP connections looking for the server indicated in the SNI extension.

