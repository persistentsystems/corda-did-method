package net.corda.did.flows
/**
 * Persistent code
 *
 */
import co.paralleluniverse.fibers.Suspendable
import com.natpryce.valueOrNull
import net.corda.core.contracts.Command
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.flows.*
import net.corda.core.transactions.SignedTransaction
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.utilities.ProgressTracker
import net.corda.did.CordaDid
import net.corda.did.utils.FlowLogicCommonMethods
import net.corda.did.contract.DidContract
import net.corda.did.state.DidState
import net.corda.did.utils.DIDNotFoundException
import java.util.*

@InitiatingFlow
@StartableByRPC
class UpdateDidFlow(val didState: DidState) : FlowLogic<SignedTransaction>(), FlowLogicCommonMethods {

    companion object {
        object GENERATING_TRANSACTION : ProgressTracker.Step("Generating transaction based on new DidState.")
        object VERIFYING_TRANSACTION : ProgressTracker.Step("Verifying contract constraints.")
        object SIGNING_TRANSACTION : ProgressTracker.Step("Signing transaction with our private key.")
        object FINALISING_TRANSACTION : ProgressTracker.Step("Obtaining notary signature and recording transaction.") {
            override fun childProgressTracker() = FinalityFlow.tracker()
        }

        fun tracker() = ProgressTracker(
                GENERATING_TRANSACTION,
                VERIFYING_TRANSACTION,
                SIGNING_TRANSACTION,
                FINALISING_TRANSACTION
        )
    }

    override val progressTracker = tracker()

    /**
     * The flow logic is encapsulated within the call() method.
     */
    @Suspendable
    override fun call(): SignedTransaction {

        // query the ledger if did exist or not
        val uuid = didState.envelope.document.UUID().valueOrNull() as UUID
        val didStates = serviceHub.loadState(UniqueIdentifier(null, uuid), DidState::class.java)

        val did = didState.envelope.document.id().valueOrNull() as CordaDid

        if( didStates.isEmpty() ) {
            throw DIDNotFoundException("DID with id ${did.toExternalForm()} does not exist")
        }
        val inputDidState = didStates.singleOrNull()!!

        // Obtain a reference to the notary we want to use.
        val notary = serviceHub.firstNotary()

        // Stage 1.
        progressTracker.currentStep = GENERATING_TRANSACTION

        // Generate an unsigned transaction.
        val txCommand = Command(DidContract.Commands.Update(didState.envelope), listOf(didState.originator.owningKey))
        val txBuilder = TransactionBuilder(notary)
                .addInputState(inputDidState)
                .addOutputState(didState, DidContract.DID_CONTRACT_ID)
                .addCommand(txCommand)

        // Stage 2.
        progressTracker.currentStep = VERIFYING_TRANSACTION
        // Verify that the transaction is valid.
        txBuilder.verify(serviceHub)

        // Stage 3.
        progressTracker.currentStep = SIGNING_TRANSACTION
        // Sign the transaction.
        val signedTx = serviceHub.signInitialTransaction(txBuilder)

        // Stage 5.
        progressTracker.currentStep = FINALISING_TRANSACTION

        val otherPartySession = didState.witnesses.map { initiateFlow(it) }.toSet()
        // Notarise and record the transaction in witness parties' vaults.
        return subFlow(FinalityFlow(signedTx, otherPartySession, FINALISING_TRANSACTION.childProgressTracker()))
    }
}

@InitiatedBy(UpdateDidFlow::class)
class UpdateDidFinalityFlowResponder(private val otherPartySession: FlowSession) : FlowLogic<Unit>() {
    @Suspendable
    override fun call() {
        subFlow(ReceiveFinalityFlow(otherPartySession))
    }
}

