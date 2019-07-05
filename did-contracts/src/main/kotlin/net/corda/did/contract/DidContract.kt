package net.corda.did.contract


import com.natpryce.*
import net.corda.core.contracts.CommandData
import net.corda.core.contracts.Contract
import net.corda.core.contracts.Requirements.using
import net.corda.core.transactions.LedgerTransaction
import net.corda.did.CordaDid
import net.corda.did.DidEnvelope
import net.corda.did.contract.DidContract.Commands.Create
import net.corda.did.state.DidState
import java.security.PublicKey

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
        class Create : Commands

        // https://w3c-ccg.github.io/did-spec/#update
        class Update : Commands

        // https://w3c-ccg.github.io/did-spec/#delete-revoke
        // TODO moritzplatt 2019-02-14 -- should this require a fully formed envelope?
        class Delete : Commands
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
        // ??? moritzplatt 2019-06-20 -- looks correct
        "DID Create transaction must be signed by the DID originator" using (setOfSigners.size == 1 && setOfSigners.contains(DIDState.originator.owningKey))

        // validate did envelope
        // ??? moritzplatt 2019-06-20 -- can be rewritten:

        //  nitesh solanki 2019-06-27 made changes as suggested
        "the envelope presented is must be valid to create" using (DIDState.envelope.validateCreation() is Success)

        // ??? moritzplatt 2019-06-20 -- verify block should throw `IllegalArgumentException`

        //  nitesh solanki 2019-06-27 made changes as suggested
        DIDState.envelope.validateCreation().map { require(it == Unit) }.onFailure { throw IllegalArgumentException("Invalid Did envelope $it") }
        "Status of newly created did must be 'VALID'" using (DIDState.isValid())
        "Originator and witness nodes should be added to the participants list" using (DIDState.participants.containsAll(DIDState.witnesses + DIDState.originator))

        // ??? moritzplatt 2019-06-20 -- unsafe cast will throw a `TypeCastException` whereas the verify block should
        // throw `IllegalArgumentException` i.e.

        //  nitesh solanki 2019-06-27 made changes as suggested
        val UUID = DIDState.envelope.document.id().onFailure { throw IllegalArgumentException("Unable to fetch UUID from did") }.uuid
        "LinearId of the DidState must be equal to the UUID component of did" using (UUID == DIDState.linearId.id)
        // ??? moritzplatt 2019-06-20 -- can use == operator

        //  nitesh solanki 2019-06-27 made changes as suggested
    }

    /**
     * Persistent code
     *
     */
    open fun verifyDidUpdate(tx: LedgerTransaction, setOfSigners: Set<PublicKey>) {

        val oldDIDState = tx.inputsOfType<DidState>().single()
        val newDIDState = tx.outputsOfType<DidState>().single()
        // ??? moritzplatt 2019-06-20 -- superfluous check. previous `single` call would already have thrown

        // TODO need to discuss on the signature requirement. How many nodes from consortium should be signing this transaction?
        // ??? moritzplatt 2019-06-20 -- this means users will always have to go through the same node for updates
        // is that a constraint we want to place on them?

        // nitesh solanki 2019-06-27 made changes as suggested

        // validate modification
        // ??? moritzplatt 2019-06-20 -- can be simplified

        // nitesh solanki 2019-06-27 made changes as suggested
        "Failed to update DID document" using (newDIDState.envelope.validateModification(oldDIDState.envelope.document) is Success)
        "Status of the precursor DID must be 'VALID'" using(oldDIDState.isValid())
        "Status of the updated DID must be 'VALID'" using(newDIDState.isValid())

        // ??? moritzplatt 2019-06-20 -- unsafe cast will throw a `TypeCastException` whereas the verify block should
        // throw `IllegalArgumentException`

        // nitesh solanki 2019-06-27 made changes as suggested
        val oldDid = oldDIDState.envelope.document.id().onFailure { throw IllegalArgumentException("Unable to fetch id from document") }
        val newDid = newDIDState.envelope.document.id().onFailure { throw IllegalArgumentException("Unable to fetch id from document") }
        "ID of the updated did document should not change" using(oldDid.toExternalForm() == newDid.toExternalForm())

        // ??? moritzplatt 2019-06-20 -- can use == operator

        // nitesh solanki 2019-06-27 made changes as suggested
        "Linear ID of the DID state should not change when updating DID document" using(oldDIDState.linearId == newDIDState.linearId)

        // TODO state participants [List] and witness nodes [Set] changes is considered as a separate update transaction and hence separate command(DIDState update)--? should this be purely DID document update transaction
        // ??? moritzplatt 2019-06-20 -- agreed. a change of witness nodes--if supported at all--should be a different command. this should be only about updates (in the sense of the spec)
        // ??? moritzplatt 2019-06-20 -- could all use ==

        // nitesh solanki 2019-06-27 made changes as suggested
        "DidState Originator should not change when updating DID document" using (oldDIDState.originator == newDIDState.originator)
        "DidState witness nodes list should not change when updating DID document" using (oldDIDState.witnesses == newDIDState.witnesses)
        "Participants list should not change when updating DID document" using(oldDIDState.participants == newDIDState.participants)
    }

    /**
     * Persistent code
     *
     */

    // ??? moritzplatt 2019-06-20 -- consider refactoring some of the joint functionality between `verifyDidUpdate` and `verifyDidDelete` to a joint method
    // Delete will just mark the state as DELETED
    open fun verifyDidDelete(tx: LedgerTransaction, setOfSigners: Set<PublicKey>) {

        val oldDIDState = tx.inputsOfType<DidState>().single()
        val newDIDState = tx.outputsOfType<DidState>().single()

        // validate modification

        // nitesh solanki 2019-06-27 made changes as suggested
        "Failed to delete DID document" using (newDIDState.envelope.validateDeletion(oldDIDState.envelope.document) is Success)
        "Status of the precursor DID must be 'VALID'" using(oldDIDState.isValid())
        "Status of the updated DID must be 'INVALID'" using(!newDIDState.isValid())

        // ??? moritzplatt 2019-06-20 -- see notes around unsafe casts/TypeCastException above

        // nitesh solanki 2019-06-27 made changes as suggested

        val oldDidKeys = oldDIDState.envelope.document.publicKeys().onFailure { throw java.lang.IllegalArgumentException("Unable to fetch public keys from document") }
        val newDidKeys = newDIDState.envelope.document.publicKeys().onFailure { throw java.lang.IllegalArgumentException("Unable to fetch public keys from document") }
        
        // ??? moritzplatt 2019-06-20 -- there was an idea earlier that for deletion you wouldn't have to produce all keys.
        // unsure where you landed on the design discussion here

        // nitesh solanki 2019-06-27 for now will stick to the design where delete operation will just mark the did as invalid. no changes to the did doc wll be made
        "Delete transaction should not change the public Keys in DID document" using(oldDidKeys == newDidKeys)

        "Linear ID of the DID state should not change when updating DID document" using(oldDIDState.linearId == newDIDState.linearId)

        "DidState Originator should not change when deleting DID" using (oldDIDState.originator == newDIDState.originator)
        "DidState witness nodes list should not change when deleting DID" using (oldDIDState.witnesses == newDIDState.witnesses)
        "Participants list should not change when deleting DID" using(oldDIDState.participants == newDIDState.participants)
    }
}