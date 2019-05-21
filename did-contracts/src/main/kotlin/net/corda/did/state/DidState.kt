package net.corda.did.state


import com.natpryce.valueOrNull
import net.corda.core.contracts.BelongsToContract
import net.corda.core.contracts.LinearState
import net.corda.core.contracts.UniqueIdentifier
import net.corda.core.identity.AbstractParty
import net.corda.core.identity.Party
import net.corda.core.schemas.MappedSchema
import net.corda.core.schemas.PersistentState
import net.corda.core.schemas.QueryableState
import net.corda.core.serialization.CordaSerializable
import net.corda.did.DidEnvelope
import net.corda.did.contract.DidContract

@BelongsToContract(DidContract::class)
data class DidState(
		val envelope: DidEnvelope,
		val originator: Party,
		val witnesses: Set<Party>,
		val status: DidStatus,
		override val linearId: UniqueIdentifier = UniqueIdentifier.fromString(envelope.document.UUID().valueOrNull().toString())
) : LinearState, QueryableState {

	override fun generateMappedObject(schema : MappedSchema) : PersistentState {
		return when (schema) {
			is DidStateSchemaV1 -> DidStateSchemaV1.PersistentDidState(
					originator = this.originator,
					didExternalForm = this.envelope.document.id().valueOrNull()!!.toExternalForm(),
					status = this.status,
					linearId = this.linearId.id
			)
			else -> throw IllegalArgumentException("Unrecognised schema $schema")
		}
	}

	override fun supportedSchemas() = listOf(DidStateSchemaV1)
	override val participants: List<AbstractParty> = (witnesses + originator).toList()
	fun isInvalid() = status == DidStatus.INVALID
	fun isValid() = status == DidStatus.VALID
}

@CordaSerializable
enum class DidStatus {
	VALID,
	INVALID
}
