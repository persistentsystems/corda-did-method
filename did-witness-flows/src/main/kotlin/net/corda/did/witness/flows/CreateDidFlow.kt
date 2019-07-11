package net.corda.did.witness.flows

import co.paralleluniverse.fibers.Suspendable
import com.natpryce.map
import com.natpryce.onFailure
import net.corda.core.contracts.Command
import net.corda.core.contracts.StateAndRef
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.flows.FinalityFlow
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.FlowSession
import net.corda.core.flows.InitiatedBy
import net.corda.core.flows.InitiatingFlow
import net.corda.core.flows.ReceiveFinalityFlow
import net.corda.core.flows.StartableByRPC
import net.corda.core.identity.CordaX500Name
import net.corda.core.identity.Party
import net.corda.core.transactions.SignedTransaction
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.utilities.ProgressTracker
import net.corda.did.DidEnvelope
import net.corda.did.contract.DidContract
import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
import net.corda.did.utils.DIDAlreadyExistException
import net.corda.did.utils.getNotaryFromConfig
import net.corda.did.utils.loadState

/**
 * Initiating flow to CREATE a DID on ledger as specified in the w3 specification.
 * Ref: https://w3c-ccg.github.io/did-spec/#create
 * The did will be created on the [DidState.originator] and [DidState.witnesses] nodes.
 *
 * @property envelope the [DidEnvelope] object.
 * @property progressTracker
 */
@InitiatingFlow
@StartableByRPC

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

		var didStates: List<StateAndRef<DidState>> = listOf()
		envelope.document.id().map {
			didStates = serviceHub.loadState(UniqueIdentifier(null, it.uuid), DidState::class.java)
		}

		val did = envelope.document.id().onFailure { throw Exception("") }

		if (didStates.isNotEmpty()) {
			throw DIDAlreadyExistException("DID with id ${did.toExternalForm()} already exist")
		}

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

/**
 * Receiver finality flow
 * @property[otherPartySession] FlowSession
 * */
@InitiatedBy(CreateDidFlow::class)
class CreateDidFinalityFlowResponder(private val otherPartySession: FlowSession) : FlowLogic<Unit>() {
	@Suspendable
	override fun call() {
		subFlow(ReceiveFinalityFlow(otherPartySession))
	}
}