package com.persistent.did.witness.flows

import co.paralleluniverse.fibers.Suspendable
import com.natpryce.onFailure
import com.persistent.did.contract.DidContract
import com.persistent.did.state.DidState
import com.persistent.did.state.DidStatus
import com.persistent.did.utils.DIDNotFoundException
import com.persistent.did.utils.InvalidDIDException
import com.persistent.did.utils.getNotaryFromConfig
import com.persistent.did.utils.loadState
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
import net.corda.core.transactions.SignedTransaction
import net.corda.core.transactions.TransactionBuilder
import net.corda.core.utilities.ProgressTracker
import net.corda.did.CordaDid
import net.corda.did.DidEnvelope
import net.corda.did.DidInstruction

/**
 * Initiating flow to DELETE a DID on ledger as specified in the w3 specification. The delete operation only deactivates the did on ledger by updating the [DidState] with status as [DidStatus.DELETED].
 * Ref: https://w3c-ccg.github.io/did-spec/#deactivate
 *
 * @property instruction The instruction JSON object containing signatures of did-owner on the did-document to be deactivated.
 * @property did the did to be deleted.
 * @property ProgressTracker for tracking the steps in transaction
 */
@InitiatingFlow
@StartableByRPC

class DeleteDidFlow(val instruction: String, val did: String) : FlowLogic<SignedTransaction>() {

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

		val cordaDID = CordaDid.parseExternalForm(did).onFailure { throw InvalidDIDException("Invalid DID passed") }

		val didStates: List<StateAndRef<DidState>> = serviceHub.loadState(UniqueIdentifier(null, cordaDID.uuid), DidState::class.java)

		if (didStates.isEmpty()) {
			throw DIDNotFoundException("DID with id $did does not exist")
		}
		val inputDidState = didStates.singleOrNull()!!

		val notary = serviceHub.getNotaryFromConfig()

		// Stage 1.
		progressTracker.currentStep = GENERATING_TRANSACTION

		// Generate an unsigned transaction.
		val txCommand = Command(DidContract.Commands.Delete(), listOf(ourIdentity.owningKey))
		val txBuilder = TransactionBuilder(notary)
				.addInputState(inputDidState)
				.addOutputState(inputDidState.state.data.copy(status = DidStatus.DELETED, envelope = DidEnvelope(DidInstruction(instruction).source, inputDidState.state.data.envelope.document.source)), DidContract.DID_CONTRACT_ID)
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

		val otherPartySession = inputDidState.state.data.witnesses.map { initiateFlow(it) }.toSet()
		// Notarise and record the transaction in witness parties' vaults.
		return subFlow(FinalityFlow(signedTx, otherPartySession, FINALISING_TRANSACTION.childProgressTracker()))
	}
}

@InitiatedBy(DeleteDidFlow::class)
/**
 * Receiver finality flow
 * @property[otherPartySession] FlowSession
 * */
class DeleteDidFinalityFlowResponder(private val otherPartySession: FlowSession) : FlowLogic<Unit>() {
	@Suspendable
	override fun call() {
		subFlow(ReceiveFinalityFlow(otherPartySession))
	}
}

