package net.corda.did

import com.grack.nanojson.JsonObject
import com.natpryce.flatMap
import com.natpryce.map
import com.natpryce.onFailure
import net.corda.core.crypto.Base58
import net.corda.did.Action.Create
import net.corda.did.Action.Delete
import net.corda.did.Action.Read
import net.corda.did.Action.Update
import net.corda.getMandatoryArray
import net.corda.getMandatoryString
import java.net.URI

class DidInstruction(json: String) : JsonBacked(json) {
	fun action(): Action = json().flatMap {
		it.getMandatoryString("action")
	}.map {
		it.toAction()
	}.onFailure {
		throw IllegalArgumentException("Instruction does not contain an action")
	}

	/**
	 * Returns a set of signatures that use a well-known [CryptoSuite]. Throws an exception if a signature with an unknown
	 * crypto suite is detected.
	 */
	fun signatures(): Set<QualifiedSignature> = json().flatMap {
		it.getMandatoryArray("signatures")
	}.map { signatures ->
		signatures.filterIsInstance(JsonObject::class.java).map { signature ->
			val suite = signature.getMandatoryString("type").map {
				CryptoSuite.fromSignatureID(it)
			}.onFailure { throw IllegalArgumentException("No signature type provided") }

			val id = signature.getMandatoryString("id").map {
				URI.create(it)
			}.onFailure { throw IllegalArgumentException("No key ID provided") }

			val value = signature.getMandatoryString("signatureBase58").map {
				Base58.decode(it)
			}.onFailure { throw IllegalArgumentException("No signature in Base58 format provided") }

			QualifiedSignature(suite, id, value)
		}.toSet()
	}.onFailure { throw IllegalArgumentException("No signatures provided") }
}

enum class Action {
	Read,
	Create,
	Update,
	Delete
}

private fun String.toAction() = when (this) {
	"read"   -> Read
	"create" -> Create
	"update" -> Update
	"delete" -> Delete
	else     -> throw IllegalArgumentException("Unknown action $this.")
}
