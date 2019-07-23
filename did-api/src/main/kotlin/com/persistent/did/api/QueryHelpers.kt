package com.persistent.did.api

import com.persistent.did.state.DidState
import com.persistent.did.state.DidStatus
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.messaging.CordaRPCOps
import net.corda.core.messaging.vaultQueryBy
import net.corda.core.node.services.vault.QueryCriteria
import net.corda.did.DidDocument

/**
 * Class with helper functions for querying ledger.
 *
 * @property proxy RPC connection object passed to the constructor.
 * */
class QueryUtil(private val proxy: CordaRPCOps) {

	/**
	 * @param[linearId] Takes uuid as input.
	 * @return Raw DID document.
	 * */
	fun getDIDDocumentByLinearId(linearId: String): String? {
		val criteria = QueryCriteria.LinearStateQueryCriteria(linearId = listOf(UniqueIdentifier.fromString(linearId)))
		val results = proxy.vaultQueryBy<DidState>(criteria).states

		val responseState = results.let {
			if (it.size != 1) {
				return null
			} else {
				val result = it.single()
				result.state
			}
		}

		if (responseState.data.status == DidStatus.DELETED) {
			return null
		}
		return responseState.data.envelope.rawDocument

	}

	/**
	 * @param[linearId] Takes uuid as input.
	 * @return  DidDocument class object.
	 * */

	fun getCompleteDIDDocumentByLinearId(linearId: String): DidDocument? {
		val criteria = QueryCriteria.LinearStateQueryCriteria(linearId = listOf(UniqueIdentifier.fromString(linearId)))
		val results = proxy.vaultQueryBy<DidState>(criteria).states
		val responseState = results.let {
			if (it.size != 1) {
				return null
			} else {
				val result = it.single()
				result.state
			}
		}
		if (responseState.data.status == DidStatus.DELETED) {
			return null
		}
		return responseState.data.envelope.document

	}

}

/** @param message Takes input as string.
 *   This class throws a custom exception for DIDDeletion
 *
 * */
class DIDDeletedException(message: String) : Exception(message)