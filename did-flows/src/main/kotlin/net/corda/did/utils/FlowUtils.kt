package net.corda.did.utils

import net.corda.core.CordaRuntimeException
import net.corda.core.contracts.ContractState
import net.corda.core.contracts.StateAndRef
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.identity.Party
import net.corda.core.node.ServiceHub
import net.corda.core.node.services.Vault
import net.corda.core.node.services.vault.QueryCriteria

interface FlowLogicCommonMethods {

    fun ServiceHub.firstNotary(): Party {
        return this.networkMapCache.notaryIdentities.firstOrNull()
                ?: throw NotaryNotFoundException("Notary not found.")
    }

    fun <T : ContractState> ServiceHub.loadState(linearId: UniqueIdentifier, clazz: Class<T>): List<StateAndRef<T>> {
        val queryCriteria = QueryCriteria.LinearStateQueryCriteria(null,
                listOf(linearId), Vault.StateStatus.UNCONSUMED, null)
        return this.vaultService.queryBy(clazz, queryCriteria).states
    }
}

class NotaryNotFoundException(override val message: String) : CordaRuntimeException(message)
class DIDAlreadyExistException(override val message: String) : CordaRuntimeException(message)
class DIDNotFoundException(override val message: String) : CordaRuntimeException(message)