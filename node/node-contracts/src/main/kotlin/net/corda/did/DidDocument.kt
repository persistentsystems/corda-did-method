package net.corda.did

import com.grack.nanojson.JsonParser
import net.corda.did.Realm.CordaNetwork
import net.corda.did.Realm.CordaNetworkUAT
import java.net.URI
import java.security.PublicKey
import java.util.UUID

/**
 * This encapsulates a DID, preserving the full JSON document as received by the owner. While it would be beneficial
 * to have a strongly typed `DidDocument` class in which the aspects of a DID are stored as individual fields, the lack
 * of a canonical JSON representation on which hashes are generated makes this problematic.
 *
 * Instead, this class provides convenience methods, that extract information from the JSON document on request. Note
 * that the document tree these operations work on will not be stored in a field to keep serialisation size small. This
 * means that usage of the convenience methods has a high computational overhead.
 */
data class DidDocument(private val document: String) {

	private val json = { JsonParser.`object`().from(document) }

	fun id(): CordaDid = json().run {
		CordaDid.fromExternalForm(getString("id"))
	}
}

data class CordaDid(
		val realm: Realm,
		val id: UUID
) {
	companion object {

		fun fromExternalForm(externalForm: String): CordaDid {
			val fragments = externalForm.split(":")

			if (fragments.size != 4)
				throw IllegalArgumentException("""Malformed Corda DID "$externalForm" provided""")

			val (scheme, methodString, realmString, idString) = fragments

			if (scheme != "did")
				throw IllegalArgumentException("Not a DID")

			if (methodString != "corda")
				throw IllegalArgumentException("""Invalid method "$methodString" provided""")

			val realm = when (realmString) {
				"tcn"     -> CordaNetwork
				"tcn-uat" -> CordaNetworkUAT
				else      -> throw IllegalArgumentException("""Invalid realm "$realmString" provided""")
			}

			val id = UUID.fromString(idString)

			return CordaDid(realm, id)

		}
	}

	fun toExternalForm(): String {
		val realmString = when (realm) {
			CordaNetwork    -> "tcn"
			CordaNetworkUAT -> "tcn-uat"
		}

		return "did:corda:$realmString:$id"
	}

	fun toURI(): URI = URI.create(toExternalForm())
}

enum class Realm {
	CordaNetwork,
	CordaNetworkUAT
}