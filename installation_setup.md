## Directory Structure
| Directory | Description                                                     |
|-----------|-----------------------------------------------------------------|
| `did-api` | Module for defining REST api.                         |
| `did-contracts` |  Module for defining Corda smart contracts.                   |
| `did-flows`     | Module for defining Corda flows for read operations.               |
| `did-envelope` | Module for defining the did envelope, document and instruction.|
| `did-witness-flows` | Module for defining Corda flows for create, update and delete operations.|

## Setup
### Pre-requisites
The CorDapp is tested against Corda OS 4.0.
Please refer to the [set up](https://docs.corda.net/getting-set-up.html) instructions.

### Build step
To build jar use command `./gradelw jar` .This will generate the following files

| File | Description                                                     |
|-----------|-----------------------------------------------------------------|
| `did-contracts-1.0-SNAPSHOT.jar` | contains state and contracts.                  |
| `did-flows-1.0-SNAPSHOT.jar` |  contains flows for read.                 |
| `did-witness-flows-1.0-SNAPSHOT.jar`| contains flows for create, update, delete.


### Running the node as witness
* Complete the [pre-requisite](https://docs.corda.net/getting-set-up.html) and [network bootstrapper](https://docs.corda.net/network-bootstrapper.html) setup.
* Create a file with name `did-witness-flows-1.0-SNAPSHOT.conf` with below content and place it under the config directory of node file system.
```bash
nodes = [
"O=PartyB,L=New York,C=US"
]

notary = "O=Notary,L=London,C=GB"

network = "tcn"
```
where nodes is a pre-defined list of witness nodes. Replace the nodes, notary and network with appropriate values
* Place the jars generated in the above build step into the cordapp directory of node file system.
* Run the corda node using `java -jar corda.jar`


### Running the Spring boot api using gradle task
* Run the command `./gradelw runPartyAServer` to start the Spring boot server on port `50005`
* Update the gradle task as required with appropriate rpc host, rpc port, rpc username, rpc password and server port.
