package net.corda.did

import java.net.URI

class Did(
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