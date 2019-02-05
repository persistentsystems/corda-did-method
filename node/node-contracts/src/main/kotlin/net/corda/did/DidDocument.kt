package net.corda.did

import com.grack.nanojson.JsonParser
import net.corda.did.CryptoSuite.values
import net.corda.getArrayOfObjects
import java.net.URI
import java.security.PublicKey
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

	fun keys(): Map<URI, PublicKey> = json().run {
		getArrayOfObjects("publicKey").map { keyJson ->
			val keyType = values().single {
				it.signatureIdentifier == keyJson.getString("type")
			}

			val uri = keyJson.getString("id").let {
				URI.create(it)
			}
			uri to keyJson.toPublicKey(keyType)
		}.toMap()
	}
}

