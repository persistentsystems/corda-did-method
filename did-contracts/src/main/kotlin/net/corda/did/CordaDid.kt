package net.corda.did

import net.corda.did.Network.CordaNetwork
import net.corda.did.Network.CordaNetworkUAT
import net.corda.did.Network.Testnet
import java.net.URI
import java.util.UUID

class CordaDid(
		externalForm: String
) {
	val did: URI = URI.create(externalForm)
	val network: Network
	val uuid: UUID

	init {
		if (did.scheme != "did")
			throw IllegalArgumentException("""DID must use the "did" scheme. Found "${did.scheme}".""")

		val regex = """did:corda:(tcn|tcn-uat|testnet):([0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12})""".toRegex()

		val (n, u) = regex.find(externalForm)?.destructured ?: throw IllegalArgumentException("Malformed Corda DID")

		network = n.toNetwork()

		uuid = try {
			UUID.fromString(u)
		} catch (e: IllegalArgumentException) {
			throw IllegalArgumentException("Third part of a Corda DID needs to be a valid UUID", e)
		}
	}

	fun toExternalForm() = did.toString()

	private fun String.toNetwork(): Network = when (this) {
		"tcn"     -> CordaNetwork
		"tcn-uat" -> CordaNetworkUAT
		"testnet" -> Testnet
		else      -> throw IllegalArgumentException(""""Unknown network "$this"""")
	}
}
