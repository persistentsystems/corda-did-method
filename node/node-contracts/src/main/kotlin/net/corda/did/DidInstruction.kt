package net.corda.did

import net.corda.did.Action.Create
import net.corda.did.Action.Delete
import net.corda.did.Action.Read
import net.corda.did.Action.Update
import java.security.Signature

class DidInstruction(json: String) : JsonBacked(json) {
	fun action(): Action = json().getString("action")?.toAction()
			?: throw IllegalArgumentException("Instruction does not contain an action")

	fun nonce(): String? = json().getString("nonce")

	/**
	 * Returns a list of signatures if all signatures adhere to the Linked Data Cryptographic Suite Registry (Draft
	 * Community Group Report 09 December 2018). Throws an exception otherwise.
	 */
	fun signatures(): List<Signature> {
		TODO()
	}
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
