/**
 * R3 copy
 *
 */

package net.corda.did

import java.net.URI

/**
 * A representation of a public key mirroring the fields outlined in the Decentralized Identifiers v0.11 Data Model
 * Draft Community Group Report 06 February 2019 (https://w3c-ccg.github.io/did-spec/#public-keys)
 */
class QualifiedPublicKey(
		val id: URI,
		val type: CryptoSuite,
		// TODO moritzplatt 2019-02-13 -- what validation to apply here?
		val controller: URI,
		val value: ByteArray
)