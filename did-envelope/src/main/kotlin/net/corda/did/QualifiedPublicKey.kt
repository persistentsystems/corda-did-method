

package net.corda.did

import java.net.URI

/**
 * A representation of a public key mirroring the fields outlined in the Decentralized Identifiers v0.11 Data Model
 * Draft Community Group Report 06 February 2019 (https://w3c-ccg.github.io/did-spec/#public-keys)
 *
 *@property[id] Uri of the target.
 *@property[type] Type of cryptographic suite being used.
 *@property[controller] Id of the controller of the public key .
 *@property[value] value of the public key in bytes.
 */
class QualifiedPublicKey(
		val id: URI,
		val type: CryptoSuite,
		// TODO moritzplatt 2019-02-13 -- what validation to apply here?
		val controller: URI,
		val value: ByteArray
) {
	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (other == null || javaClass != other.javaClass) return false
		val otherKey = other as QualifiedPublicKey
		return id == otherKey.id &&
				type == otherKey.type &&
				controller == otherKey.controller &&
				java.util.Arrays.equals(value, otherKey.value)
	}
}
