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
import net.corda.did.state.DidState

class QueryUtil(private val proxy: CordaRPCOps) {


    fun getDIDDocumentByLinearId(linearId: String): JsonObject {
        val criteria= QueryCriteria.LinearStateQueryCriteria(linearId = listOf(UniqueIdentifier.fromString(linearId)))
        val results = proxy.vaultQueryBy<DidState>(criteria).states
        try {
            val responseData = results.singleOrNull()!!.state.data.envelope.document.json
            return responseData
        }
        catch(e:NullPointerException){
             return JsonObject()
        }


    }




}