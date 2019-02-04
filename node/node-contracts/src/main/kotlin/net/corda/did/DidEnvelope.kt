package net.corda.did

import java.net.URI
import java.security.Signature

/**
 * An envelope holding a [DidDocument] in payload.
 * De-enveloping to happen in Flow.
 */
class DidEnvelope(
		private val document: DidDocument,
		private val proofs: Map<URI, Signature>
) {

}