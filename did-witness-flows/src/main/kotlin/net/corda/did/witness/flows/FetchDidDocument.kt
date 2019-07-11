package net.corda.did.witness.flows

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.flows.FlowException
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.InitiatingFlow
import net.corda.did.DidDocument
import net.corda.did.state.DidState
import net.corda.did.utils.loadState

/**
 * Initiating flow to Fetch the [DidDocument] from ledger.
 *
 * @property linearId the linearId of the [DidState].
 */
@InitiatingFlow
class FetchDidDocument(private val linearId: UniqueIdentifier) : FlowLogic<DidDocument>() {

	/**
	 * Loads the [DidState] from the ledger and returns the [DidDocument] or throws an exception if DID not found.
	 * @return [DidDocument]
	 * @throws FlowException
	 */
	@Suspendable
	override fun call(): DidDocument {
		try {
			return serviceHub.loadState(linearId, DidState::class.java).singleOrNull()!!.state.data.envelope.document
		} catch (e: Exception) {
			throw FlowException(e)
		}
	}
}