package net.corda.did

import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import com.natpryce.onFailure
import net.corda.FailureCode
import net.corda.did.CordaDidFailure.CordaDidValidationFailure.InvalidCordaDidUUIDFailure
import net.corda.did.CordaDidFailure.CordaDidValidationFailure.InvalidCordaNetworkFailure
import net.corda.did.CordaDidFailure.CordaDidValidationFailure.InvalidDidSchemeFailure
import net.corda.did.CordaDidFailure.CordaDidValidationFailure.MalformedCordaDidFailure
import net.corda.did.Network.CordaNetwork
import net.corda.did.Network.CordaNetworkUAT
import net.corda.did.Network.Testnet
import java.net.URI
import java.util.UUID

/**
 * The Corda notation for did
 *
 * @property did The instruction JSON object containing signatures of did-owner on the did-document to be deactivated.
 * @property network the target corda-network.
 * @property uuid the did to be deleted.
 */
class CordaDid(
		val did: URI,
		val network: Network,
		val uuid: UUID
) {

	/**
	 * Returns the did in external form
	 *
	 */
	fun toExternalForm() = did.toString()

	// ??? moritzplatt 2019-06-20 -- see other comments as well. consider refactoring to remove logic from init block
	// rather perform parsing from string in a dedicated method that returns a result

	// nitesh solanki 2019-06-27 made changes as suggested
	/** Contains methods for parsing from an external form of DID and an enum representing target Corda network for did*/
	companion object {

		/**
		 * Returns Success if did can be successfully parsed or returns Failure
		 *
		 * @param externalForm Did in external format
		 */
		fun parseExternalForm(externalForm: String): Result<CordaDid, CordaDidFailure> {
			val did = URI.create(externalForm)
			if (did.scheme != "did")
				return Failure(CordaDidFailure.CordaDidValidationFailure.InvalidDidSchemeFailure(did.scheme))

			val regex = """did:corda:(tcn|tcn-uat|testnet):([0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12})""".toRegex()

			val (n, u) = regex.find(externalForm)?.destructured
					?: return Failure(CordaDidFailure.CordaDidValidationFailure.MalformedCordaDidFailure())

			val network = n.toNetwork().onFailure { return it }

			val uuid = try {
				UUID.fromString(u)
			} catch (e: IllegalArgumentException) {
				return Failure(CordaDidFailure.CordaDidValidationFailure.InvalidCordaDidUUIDFailure())
			}

			return Success(CordaDid(did, network, uuid))
		}

		/**
		 * Returns an enum representing target Corda network for did
		 *
		 * @receiver [String]
		 * @return [Network]
		 *
		 */
		private fun String.toNetwork(): Result<Network, CordaDidFailure> = when (this) {
			"tcn"     -> Success(CordaNetwork)
			"tcn-uat" -> Success(CordaNetworkUAT)
			"testnet" -> Success(Testnet)
			else      -> Failure(CordaDidFailure.CordaDidValidationFailure.InvalidCordaNetworkFailure())
		}
	}
}

@Suppress("UNUSED_PARAMETER", "CanBeParameter", "MemberVisibilityCanBePrivate")
/**
 * Returns specific classes for various validation failures on Corda DID
 *
 * */
sealed class CordaDidFailure : FailureCode() {
	/**
	 * @property[InvalidDidSchemeFailure] DID must use the "did" scheme.
	 * @property[MalformedCordaDidFailure] Malformed Corda DID
	 * @property[InvalidCordaDidUUIDFailure] Malformed Corda DID UUID
	 * @property[InvalidCordaNetworkFailure] Invalid corda network
	 * */
	sealed class CordaDidValidationFailure(description: String) : CordaDidFailure() {
		class InvalidDidSchemeFailure(underlying: String) : CordaDidValidationFailure("""DID must use the "did" scheme. Found "${underlying}".""")
		class MalformedCordaDidFailure : CordaDidValidationFailure("Malformed Corda DID")
		class InvalidCordaDidUUIDFailure : CordaDidValidationFailure(" Malformed Corda DID UUID")
		class InvalidCordaNetworkFailure : CordaDidValidationFailure("Invalid corda network")
	}
}
