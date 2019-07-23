## CorDapp design -CMN views
The CorDapp functions as registry which maps decentralized identifiers to a document containing associated public keys. This needs to be deployed by any node that wants to act as a member node of a DID business network. The CorDapp consists of states, flows and contracts.
### State view 
This is the State view CMN representation of `DidState` which contains following properties:
* `Envelope`: Object encapsulating the did-document and instruction.
* `Originator`: Trusted anchor node chosen by the user.
* `Witnesses`: List of nodes that will be replicating the did.
* `LinearId`: UUID part of the did.

![State View](/cmn_diagrams/State.png)

### State evolution view
State evolution view depicts the life cycle of the DidState. 
* Upon did creation, DidState is instantiated with status as `Active`.
* Upon did update, the state is evolved with the modified did document.
* Upon did deletion, the state is evolved with status as `Deleted`.
   
![State evolution View](/cmn_diagrams/State evolution view.png)

### State machine view 
State machine view depicts how the DidState will get involved based on the constraints present in the state and contract which governs it.

![State machine view](/cmn_diagrams/State machine view.png)

### BPMN (create did process)
BPMN describes the create did process and identifies all the business events that result in an update to the ledger.

![BPMN (create did process)](/cmn_diagrams/BPMN.png)

## Transaction instance
The Transaction Instance View shows the specific Transaction that will be built for the business event. Since read operation does not result into a corda transaction there is no transaction view for read.
## Create DID transaction view 

![Create transaction instance view](/cmn_diagrams/Create-Transaction-Instance.png)

## Update DID transaction view

![Update transaction instance view](/cmn_diagrams/Update-Tranasction-Instance.png)

## Delete DID transaction view

![Delete transaction instance view](/cmn_diagrams/Delete-Transaction-Instance.png)
