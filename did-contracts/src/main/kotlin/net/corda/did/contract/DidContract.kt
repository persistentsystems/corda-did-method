package net.corda.did.contract

import com.natpryce.Success
import com.natpryce.get
import com.natpryce.mapFailure
import net.corda.core.contracts.CommandData
import net.corda.core.contracts.Contract
import net.corda.core.transactions.LedgerTransaction
import net.corda.did.DidEnvelope
import net.corda.did.contract.DidContract.Commands.Create
import net.corda.did.contract.DidContract.Commands.Delete
import net.corda.did.contract.DidContract.Commands.Update

class DidContract : Contract {

	companion object {

		@JvmStatic
		val IOU_CONTRACT_ID = "net.corda.didDocument.node.contract.DidContract"
	}

	override fun verify(tx: LedgerTransaction) {
		val command = tx.commandsOfType(Commands::class.java).single()

		when (command.value) {
			is Create -> TODO()
			is Update -> TODO()
			is Delete -> TODO()
		}

		// TODO
		//  - validate the DID satisfies the Corda DID spec
		//	- validate the ID is unassigned
		//	- validate all keys are owned by the creator
	}

	// Commands that can write DID information to the ledger.
	// Note that there is no `Read` command.
	//
	// https://w3c-ccg.github.io/did-spec/#did-operations
	interface Commands : CommandData {

		// https://w3c-ccg.github.io/did-spec/#create
		class Create(val envelope: DidEnvelope) : Commands

		// https://w3c-ccg.github.io/did-spec/#update
		class Update(val envelope: DidEnvelope) : Commands

		// https://w3c-ccg.github.io/did-spec/#delete-revoke
		// TODO moritzplatt 2019-02-14 -- should this require a fully formed envelope?
		class Delete(val envelope: DidEnvelope) : Commands

	}
}
