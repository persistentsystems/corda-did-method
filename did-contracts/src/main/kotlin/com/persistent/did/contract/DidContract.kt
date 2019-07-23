package com.persistent.did.contract

import com.natpryce.Success
import com.natpryce.map
import com.natpryce.onFailure
import com.persistent.did.contract.DidContract.Commands
import com.persistent.did.contract.DidContract.Commands.Create
import com.persistent.did.contract.DidContract.Commands.Delete
import com.persistent.did.contract.DidContract.Commands.Update
import com.persistent.did.contract.DidContract.Companion.DID_CONTRACT_ID
import com.persistent.did.state.DidState
import net.corda.core.contracts.CommandData
import net.corda.core.contracts.Contract
import net.corda.core.contracts.Requirements.using
import net.corda.core.transactions.LedgerTransaction
import net.corda.did.DidEnvelope
import java.security.PublicKey

/**
 * Contract class to govern the [DidState] evolution.
 * @property DID_CONTRACT_ID
 * @property Commands.Create Command logic to verify DID Create transaction.
 * @property Commands.Update Command logic to verify DID Update transaction.
 * @property Commands.Delete Command logic to verify DID Delete transaction.
 *
 */
open class DidContract : Contract {

	companion object {

		/**
		 * Define Contract ID
		 */
		@JvmStatic
		val DID_CONTRACT_ID = "com.persistent.did.contract.DidContract"
	}

	/**
	 * @param tx The [LedgerTransaction]
	 * @throws IllegalArgumentException
	 */
	override fun verify(tx: LedgerTransaction) {
		val command = tx.commandsOfType(Commands::class.java).single()

		when (command.value) {
			is Create -> verifyDidCreate(tx, command.signers.toSet())
			is Update -> verifyDidUpdate(tx, command.signers.toSet())
			is Delete -> verifyDidDelete(tx, command.signers.toSet())
			else      -> throw IllegalArgumentException("Unrecognized command")
		}
	}

	/**
	 * Commands that can write DID information to the ledger.
	 * Note that there is no `Read` command.
	 *
	 * Ref: https://w3c-ccg.github.io/did-spec/#did-operations
	 */
	interface Commands : CommandData {

		/**
		 * Create Command
		 * Ref: https://w3c-ccg.github.io/did-spec/#create
		 */
		class Create : Commands

		/** Update Command
		 *  Ref: https://w3c-ccg.github.io/did-spec/#create
		 */
		class Update : Commands

		/** Delete Command
		 *  Ref: https://w3c-ccg.github.io/did-spec/#deactivate
		 *
		 *  @property envelope The envelope object containing signatures on the latest did document to authenticate the delete operation
		 */
		class Delete(val envelope: DidEnvelope) : Commands
	}

	/**
	 *
	 * @param tx The [LedgerTransaction]
	 * @param setOfSigners list of signers for Create DID transaction
	 */
	open fun verifyDidCreate(tx: LedgerTransaction, setOfSigners: Set<PublicKey>) {
		val didState = tx.outputsOfType<DidState>().single()
		"DID Create transaction should have zero inputs" using (tx.inputs.isEmpty())
		"DID Create transaction should have only one output" using (tx.outputs.size == 1)

		"DID Create transaction must be signed by the DID originator" using (setOfSigners.size == 1 && setOfSigners.contains(didState.originator.owningKey))

		// validate did envelope
		"the envelope presented is must be valid to create" using (didState.envelope.validateCreation() is Success)

		didState.envelope.validateCreation().map { require(it == Unit) }.onFailure { throw IllegalArgumentException("Invalid Did envelope $it") }
		"Status of newly created did must be 'VALID'" using (didState.isActive())
		"Originator and witness nodes should be added to the participants list" using (didState.participants.containsAll(didState.witnesses + didState.originator))

		val UUID = didState.envelope.document.id().onFailure { throw IllegalArgumentException("Unable to fetch UUID from did") }.uuid
		"LinearId of the DidState must be equal to the UUID component of did" using (UUID == didState.linearId.id)

	}

	/**
	 *
	 * @param tx The [LedgerTransaction]
	 * @param setOfSigners list of signers for Update DID transaction
	 */
	open fun verifyDidUpdate(tx: LedgerTransaction, setOfSigners: Set<PublicKey>) {
		val oldDIDState = tx.inputsOfType<DidState>().single()
		val newDIDState = tx.outputsOfType<DidState>().single()

		// validate deletion
		"Failed to update DID document" using (newDIDState.envelope.validateModification(oldDIDState.envelope.document) is Success)
		"Status of the precursor DID must be 'VALID'" using (oldDIDState.isActive())
		"Status of the updated DID must be 'VALID'" using (newDIDState.isActive())

		val oldDid = oldDIDState.envelope.document.id().onFailure { throw IllegalArgumentException("Unable to fetch id from document") }
		val newDid = newDIDState.envelope.document.id().onFailure { throw IllegalArgumentException("Unable to fetch id from document") }
		"ID of the updated did document should not change" using (oldDid.toExternalForm() == newDid.toExternalForm())

		"Linear ID of the DID state should not change when updating DID document" using (oldDIDState.linearId == newDIDState.linearId)

		"DidState Originator should not change when updating DID document" using (oldDIDState.originator == newDIDState.originator)
		"DidState witness nodes list should not change when updating DID document" using (oldDIDState.witnesses == newDIDState.witnesses)
		"Participants list should not change when updating DID document" using (oldDIDState.participants == newDIDState.participants)
	}

	/**
	 *
	 * @param tx The [LedgerTransaction]
	 * @param setOfSigners list of signers for Delete DID transaction
	 */
	open fun verifyDidDelete(tx: LedgerTransaction, setOfSigners: Set<PublicKey>) {
		val oldDIDState = tx.inputsOfType<DidState>().single()
		"DidState should be expired for delete operation" using (tx.outputs.isEmpty())

		// validate deletion
		val envelope = tx.commandsOfType<Delete>().single().value.envelope
		"Failed to delete DID document" using (envelope.validateDeletion(oldDIDState.envelope.document) is Success)
		"Status of the precursor DID must be 'VALID'" using (oldDIDState.isActive())
	}
}