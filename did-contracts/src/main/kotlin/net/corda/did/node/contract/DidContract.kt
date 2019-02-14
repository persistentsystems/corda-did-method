package net.corda.did.node.contract

import net.corda.core.contracts.CommandData
import net.corda.core.contracts.Contract
import net.corda.core.transactions.LedgerTransaction
import net.corda.did.DidDocument

class DidContract : Contract {

	companion object {
		@JvmStatic
		val IOU_CONTRACT_ID = "net.corda.didDocument.node.contract.DidContract"
	}

	override fun verify(tx: LedgerTransaction) {
		// TODO
		//  - validate the DID satisfies the Corda DID spec
		//	- validate the ID is unassigned
		//	- validate all keys are owned by the creator
	}

	// https://w3c-ccg.github.io/did-spec/#did-operations
	interface Commands : CommandData {

		// https://w3c-ccg.github.io/did-spec/#create
		class Create(val didDocument: DidDocument) : Commands

		// https://w3c-ccg.github.io/did-spec/#read-verify
		class Verify(val didDocument: DidDocument) : Commands

		// https://w3c-ccg.github.io/did-spec/#update
		class Update(val didDocument: DidDocument) : Commands

		// https://w3c-ccg.github.io/did-spec/#delete-revoke
		class Revoke(val didDocument: DidDocument) : Commands
	}
}
