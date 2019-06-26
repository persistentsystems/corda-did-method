/**
* R3 copy
*
*/

package net.corda.did

import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import net.corda.FailureCode
import net.corda.JsonFailure
import net.corda.did.Network.CordaNetwork
import net.corda.did.Network.CordaNetworkUAT
import net.corda.did.Network.Testnet
import java.net.URI
import java.util.UUID

 class CordaDid(
		val did: URI,
		val network: Network,
		val uuid: UUID
) {

	 fun toExternalForm() =  did.toString()

	 // ??? moritzplatt 2019-06-20 -- see other comments as well. consider refactoring to remove logic from init block
	// rather perform parsing from string in a dedicated method that returns a result
	companion object {
		fun parseExternalForm(externalForm: String): Result<CordaDid, CordaDidFailure> {
			val did = URI.create(externalForm)
			if (did.scheme != "did")
				return Failure(CordaDidFailure.CordaDidValidationFailure.InvalidDidSchemeFailure(did.scheme))

			val regex = """did:corda:(tcn|tcn-uat|testnet):([0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12})""".toRegex()

			val (n, u) = regex.find(externalForm)?.destructured ?: return Failure(CordaDidFailure.CordaDidValidationFailure.MalformedCordaDidFailure())

			val network = n.toNetwork()

			val uuid = try {
				UUID.fromString(u)
			} catch (e: IllegalArgumentException) {
				return Failure(CordaDidFailure.CordaDidValidationFailure.InvalidCordaDidUUIDFailure())
			}

			return Success(CordaDid(did, network, uuid))
		}


		private fun String.toNetwork(): Network = when (this) {
			"tcn" -> CordaNetwork
			"tcn-uat" -> CordaNetworkUAT
			"testnet" -> Testnet
			else -> throw IllegalArgumentException(""""Unknown network "$this"""")
		}
	}
}

@Suppress("UNUSED_PARAMETER", "CanBeParameter", "MemberVisibilityCanBePrivate")
sealed class CordaDidFailure : FailureCode() {
	sealed class CordaDidValidationFailure(description: String) : CordaDidFailure()
	{
		class InvalidDidSchemeFailure(underlying: String) : CordaDidValidationFailure("""DID must use the "did" scheme. Found "${underlying}".""")
		class MalformedCordaDidFailure : CordaDidValidationFailure("Malformed Corda DID")
		class InvalidCordaDidUUIDFailure : CordaDidValidationFailure(" Malformed Corda DID UUID")

	}
}
