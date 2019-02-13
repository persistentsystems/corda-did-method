package net.corda.did

import java.net.URI

class QualifiedSignature(
		val suite: CryptoSuite,
		val target: URI,
		val value: ByteArray
)