package net.corda.did.contract


import com.natpryce.*
import net.corda.core.CordaRuntimeException
import net.corda.core.contracts.CommandData
import net.corda.core.contracts.Contract
import net.corda.core.contracts.Requirements.using
import net.corda.core.transactions.LedgerTransaction
import net.corda.did.CordaDid
import net.corda.did.DidEnvelope
import net.corda.did.QualifiedPublicKey
import net.corda.did.contract.DidContract.Commands.Create
import net.corda.did.state.DidState
import java.security.PublicKey
import java.util.*

// Make the contract open for inheritance--?
open class DidContract : Contract {

    companion object {

        @JvmStatic
        val DID_CONTRACT_ID = "net.corda.did.contract.DidContract"
    }

    override fun verify(tx: LedgerTransaction) {
        val command = tx.commandsOfType(Commands::class.java).single()

        when (command.value) {
            is Create -> verifyDidCreate(tx, command.signers.toSet())
            is Commands.Update -> verifyDidUpdate(tx, command.signers.toSet())
            is Commands.Delete -> verifyDidDelete(tx, command.signers.toSet())
            else -> throw IllegalArgumentException("Unrecognized command")
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

    /**
     * Persistent code
     *
     */
    open fun verifyDidCreate(tx: LedgerTransaction, setOfSigners: Set<PublicKey>) {

        val DIDState = tx.outputsOfType<DidState>().single()
        "DID Create transaction should have zero inputs" using (tx.inputs.isEmpty())
        "DID Create transaction should have only one output" using (tx.outputs.size == 1)
        // TODO need to discuss this
        "DID Create transaction must be signed by the DID originator" using(setOfSigners.size == 1 && setOfSigners.contains(DIDState.originator.owningKey))

        // validate did envelope
        DIDState.envelope.validateCreation().map {  require(it == Unit) }.onFailure { throw InvalidDidEnvelopeException("Invalid Did envelope $it") }
        "Status of newly created did must be 'VALID'" using(DIDState.isValid())
        "Originator and witness nodes should be added to the participants list" using(DIDState.participants.containsAll(DIDState.witnesses + DIDState.originator))
        val UUID = DIDState.envelope.document.UUID().valueOrNull() as UUID
        "LinearId of the DidState must be equal to the UUID component of did" using(UUID.equals(DIDState.linearId.id))
    }

    /**
     * Persistent code
     *
     */
    open fun verifyDidUpdate(tx: LedgerTransaction, setOfSigners: Set<PublicKey>) {

        val oldDIDState = tx.inputsOfType<DidState>().single()
        val newDIDState = tx.outputsOfType<DidState>().single()
        "DID Update transaction should have 1 input" using (tx.inputs.size == 1)
        "DID Update transaction should have only one output" using (tx.outputs.size == 1)
        // TODO need to discuss on the signature requirement. How many nodes from consortium should be signing this transaction?
        "DID Update transaction must be signed by the DID originator" using(setOfSigners.size == 1 && setOfSigners.contains(oldDIDState.originator.owningKey))

        // validate modification
        newDIDState.envelope.validateModification(oldDIDState.envelope.document).map {  require(it == Unit) }.onFailure { throw DidDocumentModificationFailure("Failed to update DID document $it") }
        "Status of the precursor DID must be 'VALID'" using(oldDIDState.isValid())
        "Status of the updated DID must be 'VALID'" using(newDIDState.isValid())

        val oldDid = oldDIDState.envelope.document.id().valueOrNull() as CordaDid
        val newDid = newDIDState.envelope.document.id().valueOrNull() as CordaDid
        "ID of the updated did document should not change" using(oldDid.toExternalForm().equals(newDid.toExternalForm()))

        "Linear ID of the DID state should not change when updating DID document" using(oldDIDState.linearId.equals(newDIDState.linearId))

        // TODO state participants [List] and witness nodes [Set] changes is considered as a separate update transaction and hence separate command(DIDState update)--? should this be purely DID document update transaction
        "DidState Originator should not change when updating DID document" using (oldDIDState.originator.equals(newDIDState.originator))
        "DidState witness nodes list should not change when updating DID document" using (oldDIDState.witnesses.equals(newDIDState.witnesses))
        "Participants list should not change when updating DID document" using(oldDIDState.participants.equals(newDIDState.participants))
    }

    /**
     * Persistent code
     *
     */

    // Delete will just mark the state as DELETED
    open fun verifyDidDelete(tx: LedgerTransaction, setOfSigners: Set<PublicKey>) {

        val oldDIDState = tx.inputsOfType<DidState>().single()
        val newDIDState = tx.outputsOfType<DidState>().single()
        "DID Delete transaction should have 1 input" using (tx.inputs.size == 1)
        "DID Delete transaction should have only one output" using (tx.outputs.size == 1)
        // TODO need to discuss on the signature requirement. How many nodes from consortium should be signing this transaction?
        "DID Delete transaction must be signed by the DID originator" using(setOfSigners.size == 1 && setOfSigners.contains(oldDIDState.originator.owningKey))

        // validate modification
        newDIDState.envelope.validateModification(oldDIDState.envelope.document).map {  require(it == Unit) }.onFailure { throw DidDocumentModificationFailure("Failed to delete DID document $it") }
        "Status of the precursor DID must be 'VALID'" using(oldDIDState.isValid())
        "Status of the updated DID must be 'INVALID'" using(!newDIDState.isValid())

        val oldDidKeys = oldDIDState.envelope.document.publicKeys().valueOrNull() as Set<QualifiedPublicKey>
        val newDidKeys = newDIDState.envelope.document.publicKeys().valueOrNull() as Set<QualifiedPublicKey>
        "Delete transaction should not change the public Keys in DID document" using(oldDidKeys.equals(newDidKeys))

        "Linear ID of the DID state should not change when updating DID document" using(oldDIDState.linearId.equals(newDIDState.linearId))

        "DidState Originator should not change when deleting DID" using (oldDIDState.originator.equals(newDIDState.originator))
        "DidState witness nodes list should not change when deleting DID" using (oldDIDState.witnesses.equals(newDIDState.witnesses))
        "Participants list should not change when deleting DID" using(oldDIDState.participants.equals(newDIDState.participants))
    }
}

/**
 * Persistent code
 *
 */
sealed class DidContractException(message: String) : CordaRuntimeException(message)
class InvalidDidEnvelopeException(override val message: String) : DidContractException(message)
class DidDocumentModificationFailure(override val message: String) : DidContractException(message)
