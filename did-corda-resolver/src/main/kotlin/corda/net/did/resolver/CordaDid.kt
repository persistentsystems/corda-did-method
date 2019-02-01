package corda.net.did.resolver

import java.util.*

/**
 * Represents a decentralised identifier in the Corda decentralised identifier system using the well-known format i.e.
 * `did:corda:e8bbf5c1-3d47-4287-9aa1-d74da32044a6`.
 */
data class CordaDid(
    val internalIdentifier: UUID
) {
    fun toExternalForm(): String {
        return "did:corda:$internalIdentifier"
    }

    companion object {
        fun fromExternalForm(externalForm: String): CordaDid = externalForm
            .split(":", limit = 3).let { (preamble, method, id) ->
                assert(preamble == "did")
                assert(method == "corda")
                UUID.fromString(id)
            }.let {
                CordaDid(it)
            }
    }
}