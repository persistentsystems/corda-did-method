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
import net.corda.did.CordaDid
import net.corda.did.DidEnvelope
import net.corda.did.contract.DidContract

/**
 * @property envelope The DidEnvelope object.
 * @property originator The Corda
 * @property witnesses Set of witness nodes who will be replicating the did.
 * @property status Status to identify the state of a did.
 * @property linearId equal to the [CordaDid.uuid].
 * @property participants Set of participants nodes who will be replicating the [DidState]
 */
@BelongsToContract(DidContract::class)
data class DidState(
		val envelope: DidEnvelope,
		val originator: Party,
		val witnesses: Set<Party>,
		val status: DidStatus,
		override val linearId: UniqueIdentifier,
		override val participants: List<AbstractParty> = (witnesses + originator).toList()
) : LinearState, QueryableState {

	/**
	 *
	 * @param schema [MappedSchema] object
	 */
	override fun generateMappedObject(schema: MappedSchema): PersistentState {
		val did = this.envelope.document.id().valueOrNull()!!.toExternalForm()
		return when (schema) {
			is DidStateSchemaV1 -> DidStateSchemaV1.PersistentDidState(
					originator = this.originator,
					didExternalForm = did,
					status = this.status,
					linearId = this.linearId.id
			)
			else                -> throw IllegalArgumentException("Unrecognised schema $schema")
		}
	}

	override fun supportedSchemas() = listOf(DidStateSchemaV1)
	fun isValid() = status == DidStatus.ACTIVE
}

/**
 *
 * Enum to represent the status of [DidState]
 */
@CordaSerializable
enum class DidStatus {
	// ??? moritzplatt 2019-06-20 -- misleading naming as this clashes with the concept of 'validity' of an envelope.
	// consider 'ACTIVE'

	// nitesh solanki 2019-06-27 made changes as suggested
	ACTIVE,
	DELETED
}
