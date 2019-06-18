package net.corda.did.api
/**
 * Persistent code
 *
 */
import com.grack.nanojson.JsonObject
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.messaging.CordaRPCOps
import net.corda.core.messaging.vaultQueryBy
import net.corda.core.node.services.vault.QueryCriteria
import net.corda.did.DidDocument
import net.corda.did.state.DidState
import net.corda.did.state.DidStatus

class QueryUtil(private val proxy: CordaRPCOps) {


    fun getDIDDocumentByLinearId(linearId: String): JsonObject {
        val criteria= QueryCriteria.LinearStateQueryCriteria(linearId = listOf(UniqueIdentifier.fromString(linearId)))
        val results = proxy.vaultQueryBy<DidState>(criteria).states
        try {
            val responseState = results.singleOrNull()!!.state
            if(responseState.data.status == DidStatus.DELETED){
                throw  DIDDeletedException( " Provided DID is deleted ")
            }
            return responseState.data.envelope.document.json

        }
        catch(e : NullPointerException){
             return JsonObject()
        }


    }
    fun getCompleteDIDDocumentByLinearId( linearId: String ): DidDocument {
        val criteria = QueryCriteria.LinearStateQueryCriteria(linearId = listOf(UniqueIdentifier.fromString(linearId)))
        val results = proxy.vaultQueryBy<DidState>(criteria).states
        val responseState = results.singleOrNull()!!.state
        if(responseState.data.status == DidStatus.DELETED){
                throw  DIDDeletedException( "Provided DID is deleted" )
        }
        return responseState.data.envelope.document

    }





}

class DIDDeletedException(message:String):Exception(message)