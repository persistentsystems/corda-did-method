package net.corda.did

import com.grack.nanojson.JsonObject
import net.corda.core.crypto.Base58
import net.corda.did.Action.Create
import net.corda.did.Action.Delete
import net.corda.did.Action.Read
import net.corda.did.Action.Update
import java.net.URI

class DidInstruction(json: String) : JsonBacked(json) {
	fun action(): Action = json().getString("action")?.toAction()
			?: throw IllegalArgumentException("Instruction does not contain an action")
	
	/**
	 * Returns a set of signatures that use a well-known [CryptoSuite]. Throws an exception if a signature with an unknown
	 * crypto suite is detected.
	 */
	fun signatures(): Set<QualifiedSignature> = json().getArray("signatures").filterIsInstance(JsonObject::class.java).map { signature ->
		val suite = signature.getString("type")?.let { CryptoSuite.fromSignatureID(it) }
				?: throw IllegalArgumentException("No signature type provided")

		val id = signature.getString("id")?.let(::URI)
				?: throw IllegalArgumentException("No key ID provided")

		val value = signature.getString("signatureBase58")?.let {
			Base58.decode(it)
		} ?: throw IllegalArgumentException("No signature in Base58 format provided")

		QualifiedSignature(suite, id, value)
	}.toSet()
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
