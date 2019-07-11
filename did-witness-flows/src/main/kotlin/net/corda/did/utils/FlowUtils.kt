package net.corda.did.utils

import net.corda.core.CordaRuntimeException
import net.corda.core.contracts.ContractState
import net.corda.core.contracts.LinearState
import net.corda.core.contracts.StateAndRef
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.identity.CordaX500Name
import net.corda.core.identity.Party
import net.corda.core.node.ServiceHub
import net.corda.core.node.services.Vault
import net.corda.core.node.services.vault.QueryCriteria


// methods just as well

/**
 * returns a notary from cordapp-config file or throws an exception if notary not found in the nodes network map cache.
 *
 * @receiver [ServiceHub]
 * @return [Party]
 * @throws NotaryNotFoundException
 */
fun ServiceHub.getNotaryFromConfig(): Party? {
	val config = this.getAppContext().config
	val notary = config.get("notary")
	return this.networkMapCache.getNotary(CordaX500Name.parse(notary.toString()))
			?: throw NotaryNotFoundException("Notary not found")
}

/**
 * returns list of [StateAndRef] for given linearId
 *
 * @param T the type of state
 * @param linearId the linearId of the [LinearState] to be queried
 * @receiver [ServiceHub]
 * @return [List<StateAndRef>]
 */
fun <T : ContractState> ServiceHub.loadState(linearId: UniqueIdentifier, clazz: Class<T>): List<StateAndRef<T>> {
	val queryCriteria = QueryCriteria.LinearStateQueryCriteria(null,
			listOf(linearId), Vault.StateStatus.UNCONSUMED, null)
	return this.vaultService.queryBy(clazz, queryCriteria).states
}

class NotaryNotFoundException(override val message: String) : CordaRuntimeException(message)
class DIDAlreadyExistException(override val message: String) : CordaRuntimeException(message)
class DIDNotFoundException(override val message: String) : CordaRuntimeException(message)
class InvalidDIDException(override val message: String) : CordaRuntimeException(message)