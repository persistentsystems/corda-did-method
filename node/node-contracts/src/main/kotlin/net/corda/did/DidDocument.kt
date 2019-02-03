package net.corda.did

import com.grack.nanojson.JsonParser

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

	private val json = { JsonParser.`object`().from(document) }

	fun id(): Did = json().run {
		Did(getString("id"))
	}
}
