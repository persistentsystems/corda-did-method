package net.corda.did.flows

import co.paralleluniverse.fibers.Suspendable
import com.natpryce.map
import com.natpryce.onFailure
import net.corda.core.contracts.Command
import net.corda.core.contracts.StateAndRef
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.flows.*
import net.corda.core.identity.CordaX500Name
import net.corda.core.identity.Party
import net.corda.core.transactions.SignedTransaction
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.utilities.ProgressTracker
import net.corda.did.DidEnvelope
import net.corda.did.utils.DIDAlreadyExistException
import net.corda.did.utils.*
import net.corda.did.contract.DidContract
import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
import kotlin.collections.ArrayList


/**
 * Initiating flow to CREATE a DID on ledger as specified in the w3 specification.
 * Ref: https://w3c-ccg.github.io/did-spec/#create
 * The did will be created on the [DidState.originator] and [DidState.witnesses] nodes.
 *
 * @property envelope the [DidEnvelope] object.
 */
@InitiatingFlow
@StartableByRPC
// ??? moritzplatt 2019-06-20 -- I'm unsure about passing a Fully formed `DidState` to the flow constructor
// This assumes the caller can set originator, witnesses, participants which is not likely something we want to be set
// from the outside. These fields should rather be generated in the flow itself.
// i.e., consider the following constructor
//
//  class CreateDidFlow(val envelope: DidEnvelope) : FlowLogic<SignedTransaction>(), FlowLogicCommonMethods {
//
// then extract the parameters as follows:
//
//      DidState.originator: serviceHub.myInfo.legalIdentities.first()
//      DidState.witnesses: By configuration
//      DidState.status: envelope.instruction
//      DidState.linearId: UniqueIdentifier(null, envelope.document.id())
//      DidState.participants: implicit



// nitesh solanki 2019-06-27 made changes as suggested
class CreateDidFlow(val envelope: DidEnvelope) : FlowLogic<SignedTransaction>() {

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

        // ??? moritzplatt 2019-06-20 -- calling both `UUID()` and `id()` seems like unnecessary duplication
        // i.e.:
        //
        //        didState.envelope.document.id().map {
        //            serviceHub.loadState(UniqueIdentifier(null, it.uuid), DidState::class.java)
        //        }


        // nitesh solanki 2019-06-27 made changes as suggested

        var didStates: List<StateAndRef<DidState>> = listOf()
        envelope.document.id().map {
            didStates = serviceHub.loadState(UniqueIdentifier(null, it.uuid), DidState::class.java)
        }

        val did = envelope.document.id().onFailure { throw Exception("") }

        if(didStates.isNotEmpty()) {
            throw DIDAlreadyExistException("DID with id ${did.toExternalForm()} already exist")
        }

        // Obtain a reference to the notary we want to use.
        // ??? moritzplatt 2019-06-20 -- the preferred notary should come from configuration
        // see https://corda.network/participation/notary-considerations.html#guidance-for-application-developers for
        // reasoning


        // nitesh solanki 2019-06-27 made changes as suggested
        val notary = serviceHub.getNotaryFromConfig()

        // Stage 1.
        progressTracker.currentStep = GENERATING_TRANSACTION

        val config = serviceHub.getAppContext().config
        val nodes = config.get("nodes") as ArrayList<*>
        val witnessNodesList = arrayListOf<Party>()
       for (any in nodes.toSet()) {
           witnessNodesList.add(serviceHub.networkMapCache.getPeerByLegalName(CordaX500Name.parse(any.toString()))!!)
       }

        val didState = DidState(envelope, serviceHub.myInfo.legalIdentities.first(), witnessNodesList.toSet(), DidStatus.ACTIVE, UniqueIdentifier(null, did.uuid))
        // Generate an unsigned transaction.
        val txCommand = Command(DidContract.Commands.Create(), listOf(ourIdentity.owningKey))
        val txBuilder = TransactionBuilder(notary)
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

        val otherPartySession = didState.witnesses.minus(ourIdentity).map { initiateFlow(it) }.toSet()

        // Notarise and record the transaction in witness parties' vaults.
        return subFlow(FinalityFlow(signedTx, otherPartySession, FINALISING_TRANSACTION.childProgressTracker()))
    }
}

@InitiatedBy(CreateDidFlow::class)
class CreateDidFinalityFlowResponder(private val otherPartySession: FlowSession) : FlowLogic<Unit>() {
    @Suspendable
    override fun call() {
        subFlow(ReceiveFinalityFlow(otherPartySession))
    }
}