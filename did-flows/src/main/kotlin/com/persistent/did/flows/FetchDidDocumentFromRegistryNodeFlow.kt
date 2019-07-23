package com.persistent.did.flows

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.InitiatingFlow
import net.corda.core.flows.StartableByRPC
import net.corda.core.identity.Party
import net.corda.core.utilities.ProgressTracker
import net.corda.core.utilities.unwrap
import net.corda.did.DidDocument
import java.util.UUID

/** Initiating flow to fetch a did document from did-registry node.
 * Any flow that wishes to receive did document from a did-registry node has to invoke this as a sub-flow.
 *
 * @property didRegistryNode did registry node
 * @property did the UUID part of the did to be queried for
 */
@InitiatingFlow
@StartableByRPC
class FetchDidDocumentFromRegistryNodeFlow(private val didRegistryNode: Party, private val did: UUID) : FlowLogic<DidDocument>() {

	@Suppress("ClassName")
	companion object {
		object INITIATING_FLOW_SESSION : ProgressTracker.Step("Initiating flow session with did-registry node")
		object SENDING_AND_RECEIVING : ProgressTracker.Step("Fetching DID from vault")
	}

	override val progressTracker = ProgressTracker(INITIATING_FLOW_SESSION, SENDING_AND_RECEIVING)

	/**
	 * Starts flow session with did-registry node and receives the did document
	 *
	 * @return [DidDocument]
	 */
	@Suspendable
	override fun call(): DidDocument {

		progressTracker.currentStep = INITIATING_FLOW_SESSION
		val didRegistryNodeSession = initiateFlow(didRegistryNode)

		progressTracker.currentStep = SENDING_AND_RECEIVING
		return didRegistryNodeSession.sendAndReceive<DidDocument>(UniqueIdentifier(null, did)).unwrap { it }
	}
}