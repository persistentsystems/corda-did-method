package net.corda.did.witness.flows

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.flows.FlowException
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.FlowSession
import net.corda.core.flows.InitiatedBy
import net.corda.core.utilities.ProgressTracker
import net.corda.core.utilities.unwrap
import net.corda.did.DidDocument
import net.corda.did.flows.FetchDidDocumentFromRegistryNodeFlow
import net.corda.did.state.DidState
import net.corda.did.utils.loadState

/**
 * InitiatedBy flow to Fetch the [DidDocument] from ledger. This is a responder flow implementation for nodes attempting to query for [DidDocument] from the did-registry Business network.
 * This feature is required to support interoperability between different CorDapps that depends on the [DidDocument].
 *
 * Use case: a Business Network running a Trade Finance CorDapp may have a constraint in the smart contract to verify the digital signature of end-user represented as a did on ledger. a TF CorDapp can create a session with the did-registry node that is part of another Business Network to
 * fetch the [DidDocument] and hence obtain the publicKey needed to verify the signature.
 *
 * @property session the flow session between initiator and responder.
 */
@InitiatedBy(FetchDidDocumentFromRegistryNodeFlow::class)
class FetchDidDocumentFromRegistryNodeResponderFlow(private val session: FlowSession) : FlowLogic<Unit>() {

	companion object {
		object RECEIVING : ProgressTracker.Step("Receiving DID request")
		object FETCHING : ProgressTracker.Step("Fetching DID from vault")
		object SENDING : ProgressTracker.Step("Sending DID Document")
	}

	override val progressTracker = ProgressTracker(RECEIVING, FETCHING, SENDING)

	/**
	 * Loads the [DidState] from the ledger and returns the [DidDocument] or throws an exception if DID not found.
	 * @throws FlowException
	 */
	@Suspendable
	override fun call() {
		progressTracker.currentStep = RECEIVING
		val linearId = session.receive<UniqueIdentifier>().unwrap { it }

		progressTracker.currentStep = FETCHING
		val response = try {
			serviceHub.loadState(linearId, DidState::class.java).singleOrNull()!!.state.data.envelope.document
		} catch (e: Exception) {
			throw FlowException(e)
		}

		progressTracker.currentStep = SENDING
		session.send(response)
	}
}