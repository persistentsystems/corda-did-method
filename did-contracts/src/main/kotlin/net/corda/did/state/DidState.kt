/**
 * R3 copy
 *
 */
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
		override val linearId: UniqueIdentifier ,
		override val participants: List<AbstractParty> = (witnesses + originator).toList()
) : LinearState, QueryableState {

	/**
	 * Persistent code
	 *
	 */
	override fun generateMappedObject(schema : MappedSchema) : PersistentState {
		val did = this.envelope.document.id().valueOrNull()!!.toExternalForm()
		return when (schema) {
			is DidStateSchemaV1 -> DidStateSchemaV1.PersistentDidState(
					originator = this.originator,
					didExternalForm = did,
					status = this.status,
					linearId = this.linearId.id
			)
			else -> throw IllegalArgumentException("Unrecognised schema $schema")
		}
	}

	override fun supportedSchemas() = listOf(DidStateSchemaV1)
	fun isValid() = status == DidStatus.ACTIVE
}

/**
 * Persistent code
 *
 */
@CordaSerializable
enum class DidStatus {
	// ??? moritzplatt 2019-06-20 -- misleading naming as this clashes with the concept of 'validity' of an envelope.
	// consider 'ACTIVE'
	ACTIVE,
	DELETED
}
