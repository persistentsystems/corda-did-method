package net.corda.did

import com.grack.nanojson.JsonObject
import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import com.natpryce.flatMap
import com.natpryce.map
import com.natpryce.mapFailure
import com.natpryce.onFailure
import net.corda.FailureCode
import net.corda.JsonFailure
import net.corda.did.Action.Create
import net.corda.did.Action.Delete
import net.corda.did.Action.Read
import net.corda.did.Action.Update
import net.corda.did.DidInstructionFailure.InvalidInstructionJsonFailure
import net.corda.getMandatoryArray
import net.corda.getMandatoryBase58Bytes
import net.corda.getMandatoryCryptoSuiteFromSignatureID
import net.corda.getMandatoryString
import net.corda.getMandatoryUri

class DidInstruction(json: String) : JsonBacked(json) {
	fun action(): DidInstructionResult<Action> = json().flatMap {
		it.getMandatoryString("action")
	}.mapFailure {
		InvalidInstructionJsonFailure(it)
	}.flatMap {
		it.toAction()
	}

	/**
	 * Returns a set of signatures that use a well-known [CryptoSuite]. Throws an exception if a signature with an
	 * unknown crypto suite is detected.
	 */
	fun signatures(): DidInstructionResult<Set<QualifiedSignature>> = json().flatMap {
		it.getMandatoryArray("signatures")
	}.mapFailure {
		InvalidInstructionJsonFailure(it)
	}.map { signatures ->
		signatures.filterIsInstance(JsonObject::class.java).map { signature ->
			val suite = signature.getMandatoryCryptoSuiteFromSignatureID("type").mapFailure {
				InvalidInstructionJsonFailure(it)
			}.onFailure { return it }

			val id = signature.getMandatoryUri("id").mapFailure {
				InvalidInstructionJsonFailure(it)
			}.onFailure { return it }

			val value = signature.getMandatoryBase58Bytes("signatureBase58").mapFailure {
				InvalidInstructionJsonFailure(it)
			}.onFailure { return it }

			QualifiedSignature(suite, id, value)
		}.toSet()
	}
}

enum class Action {
	Read,
	Create,
	Update,
	Delete
}

private fun String.toAction(): DidInstructionResult<Action> = when (this) {
	"read"   -> Success(Read)
	"create" -> Success(Create)
	"update" -> Success(Update)
	"delete" -> Success(Delete)
	else     -> Failure(DidInstructionFailure.UnknownActionFailure(this))
}

@Suppress("UNUSED_PARAMETER", "unused")
sealed class DidInstructionFailure : FailureCode() {
	class InvalidInstructionJsonFailure(val underlying: JsonFailure) : DidInstructionFailure()
	class UnknownActionFailure(val action: String) : DidInstructionFailure()
}

private typealias DidInstructionResult<T> = Result<T, DidInstructionFailure>
