package net.corda.did.api
/**
 * Persistent code
 *
 */

import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.messaging.CordaRPCOps
import net.corda.core.messaging.vaultQueryBy
import net.corda.core.node.services.vault.QueryCriteria
import net.corda.did.DidDocument
import net.corda.did.state.DidState
import net.corda.did.state.DidStatus
/**
 * Class with helper functions for querying ledger.
 * @property proxy RPC connection object passed to the constructor.
 * */
class QueryUtil(private val proxy: CordaRPCOps) {

     /**
      * @param[linearId] Takes uuid as input.
      * @return Raw DID document.
      * */
    fun getDIDDocumentByLinearId(linearId: String): String {
        val criteria= QueryCriteria.LinearStateQueryCriteria(linearId = listOf(UniqueIdentifier.fromString(linearId)))
        val results = proxy.vaultQueryBy<DidState>(criteria).states
        try {
            val responseState = results.singleOrNull()!!.state
            if(responseState.data.status == DidStatus.DELETED){
                throw  DIDDeletedException( APIMessage.DID_DELETED.message)
            }
            return responseState.data.envelope.rawDocument

        }
        catch(e : NullPointerException){
             return ""
        }


    }
    /**
     * @param[linearId] Takes uuid as input.
     * @return  DidDocument class object.
     * */
    fun getCompleteDIDDocumentByLinearId( linearId: String ): DidDocument {
        val criteria = QueryCriteria.LinearStateQueryCriteria(linearId = listOf(UniqueIdentifier.fromString(linearId)))
        val results = proxy.vaultQueryBy<DidState>(criteria).states
        val responseState = results.singleOrNull()!!.state
        if(responseState.data.status == DidStatus.DELETED){
                throw  DIDDeletedException(  APIMessage.DID_DELETED.message )
        }
        return responseState.data.envelope.document

    }





}
/** @param message Takes input as string.
 *   This class throws a custom exception for DIDDeletion
 *
 * */
class DIDDeletedException(message:String):Exception(message)