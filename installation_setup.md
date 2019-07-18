

## Directory Structure
| Directory | Description                                                     |
|-----------|-----------------------------------------------------------------|
| `did-api` | Module for defining REST api                         |
| `did-contracts` |  Module for defining Corda smart contracts.                   |
| `did-flows`     | Module for defining Corda flows for read operations.               |
| `did-envelope` | Module for defining the did envelope, document and instruction|
| `did-witness-flows` | Module for defining Corda flows for create,update and delete operations|

## Setup
### Pre-requisites
Please refer to the [set up](https://docs.corda.net/getting-set-up.html) instructions.

### Build step
To build jar use command `./gradelw jar` .This will generate the following files

| File | Description                                                     |
|-----------|-----------------------------------------------------------------|
| `did-contracts-1.0-SNAPSHOT.jar` | contains state and contracts                  |
| `did-flows-1.0-SNAPSHOT.jar` |  contains flows for read                 |
| `did-witness-flows-1.0-SNAPSHOT.jar`| contains flows for create,update,delete


### Running the node as witness
The nodes need to have a config file with list of witness nodes. Example configuration shown below
```bash
nodes = [
"O=PartyB,L=New York,C=US"
]

notary = "O=Notary,L=London,C=GB"
```