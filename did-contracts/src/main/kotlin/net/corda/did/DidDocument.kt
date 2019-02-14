package net.corda.did

import com.grack.nanojson.JsonObject
import com.grack.nanojson.JsonParser
import net.corda.core.crypto.Base58
import java.net.URI
import java.time.Instant
import javax.xml.bind.DatatypeConverter
import kotlin.text.Charsets.UTF_8

/**
 * This encapsulates a DID, preserving the full JSON document as received by the owner. While it would be beneficial to
 * have a strongly typed `DidDocument` class in which the aspects of a DID are stored as individual fields, the lack of
 * a canonical JSON representation on which hashes are generated makes this problematic.
 *
 * Instead, this class provides convenience methods, that extract information from the JSON document on request. Note
 * that the document tree these operations work on will not be stored in a field to keep serialisation size small. This
 * means that usage of the convenience methods has a high computational overhead.
 */
data class DidDocument(private val document: String) {
	val bytes = document.toByteArray(UTF_8)

	private val json = { JsonParser.`object`().from(document) }

	fun id(): Did = json().run {
		Did(getString("id"))
	}

	fun publicKeys(): Set<QualifiedPublicKey> = json().getArray("publicKey").filterIsInstance(JsonObject::class.java).map { publicKey ->
		val id = publicKey.getString("id")?.let(::URI)
				?: throw IllegalArgumentException("No key ID provided")

		val suite = publicKey.getString("type")?.let { CryptoSuite.fromKeyID(it) }
				?: throw IllegalArgumentException("No signature type provided")

		val controller = publicKey.getString("controller")?.let(::URI)
				?: throw IllegalArgumentException("No controller ID provided")

		// TODO moritzplatt 2019-02-13 -- Support other encodings
		val value = publicKey.getString("publicKeyBase58")?.let {
			Base58.decode(it)
		} ?: throw IllegalArgumentException("No signature in Base58 format provided")

		QualifiedPublicKey(id, suite, controller, value)
	}.toSet()

	// These (by design) drops time zone information as we are only interested in a before/after relationship of
	// instants.
	fun created(): Instant? = getTimestamp("created")

	fun updated(): Instant? = getTimestamp("updated")

	private fun getTimestamp(field: String) = json().getString(field)?.let {
		DatatypeConverter.parseDateTime(it)
	}?.toInstant()
}

