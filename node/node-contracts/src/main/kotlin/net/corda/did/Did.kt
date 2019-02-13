package net.corda.did

import java.net.URI
import java.util.UUID

open class Did(
		externalForm: String
) {
	private val did = URI.create(externalForm)

	init {
		if (did.scheme != "did")
			throw IllegalArgumentException("""DID must use the "did" scheme. Found "${did.scheme}".""")
	}

	fun toUri() = did
	fun toExternalForm() = did.toString()
}

class CordaDid(network: Network, id: UUID) : Did("did:corda:${network.externalForm}:$id")

enum class Network(val externalForm: String) {
	Testnet("testnet"),
	CordaNetworkUAT("tcn-uat"),
	CordaNetwork("tcn")
}