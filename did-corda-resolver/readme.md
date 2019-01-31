DID Corda Resolver
==================


Configuration of Target Nodes
-----------------------------

The host names of well-known target nodes are stored in [nodes](src/main/resources/nodes) in the form of a tab-separated list.

TODO:
 - Implement a proper selection strategy (so far, a random server is selected per request)
 - Implement fingerprinting of the target servers. Storing a cryptographic attribute with their host name
