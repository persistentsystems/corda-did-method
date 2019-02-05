package net.corda.did

import java.net.URI

/**
 * An envelope holding a [DidDocument] in payload.
 * De-enveloping to happen in Flow.
 */
class DidEnvelope(
		private val document: DidDocument,
		private val proofs: Map<URI, ByteArray>
) {
	fun hasIntegrity(): Boolean {
		// The keys embedded in the DID document
		val documentKeys = document.keys()

		// 1 - check the number of proofs matches the number of keys in the document
		if (proofs.size != documentKeys.size)
			return false

		// 2 - check that each proof key ID has a corresponding key in the document
		if (!proofs.keys.containsAll(documentKeys.keys))
			return false

		// 3 - check that each of the proofs contains a valid signature over the DID document
		return documentKeys.all { (reference, publicKey) ->
			val signature = proofs[reference]!!

			val suite = CryptoSuite.values().single {
				it.algorithm == publicKey.algorithm
			}

			signature.isValidSignature(document.bytes, publicKey)
		}
	}
}
