package net.corda.did

import com.grack.nanojson.JsonObject
import com.natpryce.flatMap
import com.natpryce.map
import com.natpryce.onFailure
import net.corda.core.crypto.Base58
import net.corda.getMandatoryArray
import net.corda.getMandatoryString
import java.net.URI
import java.time.Instant
import javax.xml.bind.DatatypeConverter

/**
 * This encapsulates a DID, preserving the full JSON document as received by the owner. While it would be beneficial to
 * have a strongly typed `DidDocument` class in which the aspects of a DID are stored as individual fields, the lack of
 * a canonical JSON representation on which hashes are generated makes this problematic.
 *
 * Instead, this class provides convenience methods, that extract information from the JSON document on request. Note
 * that the document tree these operations work on will not be stored in a field to keep serialisation size small. This
 * means that usage of the convenience methods has a high computational overhead.
 */
class DidDocument(document: String) : JsonBacked(document) {

	fun id(): Did {
		return json().flatMap {
			it.getMandatoryString("id")
		}.map {
			Did(it)
		}.onFailure {
			throw IllegalArgumentException()
		}
	}

	fun publicKeys(): Set<QualifiedPublicKey> = json().flatMap {
		it.getMandatoryArray("publicKey")
	}.map { keys ->
		keys.filterIsInstance(JsonObject::class.java).map { key ->
			val id = key.getMandatoryString("id")
					.map(::URI)
					.onFailure { throw IllegalArgumentException("No key ID provided") }

			val suite = key.getMandatoryString("type")
					.map { CryptoSuite.fromKeyID(it) }
					.onFailure { throw IllegalArgumentException("No signature type provided") }

			val controller = key.getMandatoryString("controller")
					.map(::URI)
					.onFailure { throw IllegalArgumentException("No controller ID provided") }

			// TODO moritzplatt 2019-02-13 -- Support other encodings
			val value = key.getMandatoryString("publicKeyBase58")
					.map { Base58.decode(it) }
					.onFailure { throw IllegalArgumentException("No signature in Base58 format provided") }

			QualifiedPublicKey(id, suite, controller, value)
		}.toSet()
	}.onFailure { throw IllegalArgumentException() }

	// These (by design) drop time zone information as we are only interested in a before/after relationship of
	// instants.
	fun created(): Instant? = getTimestamp("created").onFailure { throw IllegalArgumentException() }

	fun updated(): Instant? = getTimestamp("updated").onFailure { throw IllegalArgumentException() }

	private fun getTimestamp(field: String) = json().map {
		it.getString(field)?.let {
			DatatypeConverter.parseDateTime(it)
		}?.toInstant()
	}
}

