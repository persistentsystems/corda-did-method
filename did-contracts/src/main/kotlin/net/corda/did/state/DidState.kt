package net.corda.did.state

import net.corda.core.contracts.BelongsToContract
import net.corda.core.contracts.LinearState
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.identity.AbstractParty
import net.corda.core.identity.Party
import net.corda.did.DidEnvelope
import net.corda.did.contract.DidContract

@BelongsToContract(DidContract::class)
class DidState(
		val envelope: DidEnvelope,
		val originator: Party,
		val witnesses: Set<Party>,
		override val linearId: UniqueIdentifier = UniqueIdentifier()
) : LinearState {
	override val participants: List<AbstractParty> = (witnesses + originator).toList()
}