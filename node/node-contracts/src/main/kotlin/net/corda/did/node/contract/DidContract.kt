package net.corda.did.node.contract

import net.corda.core.contracts.CommandData
import net.corda.core.contracts.Contract
import net.corda.core.transactions.LedgerTransaction
import net.corda.did.Did

class DidContract : Contract {

    companion object {
        @JvmStatic
        val IOU_CONTRACT_ID = "net.corda.did.node.contract.DidContract"
    }

    override fun verify(tx: LedgerTransaction) {
        // TODO
    }

    // https://w3c-ccg.github.io/did-spec/#did-operations
    interface Commands : CommandData {

        // https://w3c-ccg.github.io/did-spec/#create
        class Create(val did: Did) : Commands

        // https://w3c-ccg.github.io/did-spec/#read-verify
        class Verify(val did: Did) : Commands

        // https://w3c-ccg.github.io/did-spec/#update
        class Update(val did: Did) : Commands

        // https://w3c-ccg.github.io/did-spec/#delete-revoke
        class Revoke(val did: Did) : Commands
    }
}
