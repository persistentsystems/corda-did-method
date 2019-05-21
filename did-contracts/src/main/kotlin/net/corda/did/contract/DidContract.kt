package net.corda.did.contract


import com.natpryce.*
import net.corda.core.CordaRuntimeException
import net.corda.core.contracts.CommandData
import net.corda.core.contracts.Contract
import net.corda.core.contracts.Requirements.using
import net.corda.core.transactions.LedgerTransaction
import net.corda.did.DidEnvelope
import net.corda.did.contract.DidContract.Commands.Create
import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
import java.security.PublicKey

open class DidContract : Contract {

    companion object {

        @JvmStatic
        val DID_CONTRACT_ID = "net.corda.did.contract.DidContract"
    }

    override fun verify(tx: LedgerTransaction) {
        val command = tx.commandsOfType(Commands::class.java).single()

        when (command.value) {
            is Create -> verifyDidCreate(tx, command.signers.toSet())
            //is Update -> TODO()
            //is Delete -> TODO()
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

    open fun verifyDidCreate(tx: LedgerTransaction, setOfSigners: Set<PublicKey>) {

        val DIDState = tx.outputsOfType<DidState>().single()
        "DID Create transaction should have zero inputs" using (tx.inputs.isEmpty())
        "DID Create transaction should have only one output" using (tx.outputs.size == 1)
        "DID Create transaction must be signed by the DID originator" using(setOfSigners.size == 1 && setOfSigners.contains(DIDState.originator.owningKey))

        // validate did envelope
        DIDState.envelope.validateCreation().map {  require(it == Unit) }.onFailure { throw InvalidDidEnvelopeException("Invalid Did envelope") }
        "Status of newly created did must be 'VALID'" using(DIDState.status == DidStatus.VALID)
    }
}

sealed class DidContractException(message: String) : CordaRuntimeException(message)
class InvalidDidEnvelopeException(override val message: String) : DidContractException(message)
