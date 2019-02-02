package net.corda.did.node.state

import net.corda.core.contracts.BelongsToContract
import net.corda.core.contracts.LinearState
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.identity.AbstractParty
import net.corda.core.identity.Party
import net.corda.did.Condition
import net.corda.did.DidDocument
import net.corda.did.node.contract.DidContract

@BelongsToContract(DidContract::class)
class DidState(
        val didDocument: DidDocument,
        val condition: Condition,
        val originator: Party,
        val witnesses: Set<Party>,
        override val linearId: UniqueIdentifier = UniqueIdentifier()
) : LinearState {
    override val participants: List<AbstractParty> = (witnesses + originator).toList()
}