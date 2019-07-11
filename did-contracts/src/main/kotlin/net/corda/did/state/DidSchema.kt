package net.corda.did.state

import net.corda.core.identity.Party
import net.corda.core.schemas.MappedSchema
import net.corda.core.schemas.PersistentState
import net.corda.core.serialization.CordaSerializable
import java.util.UUID
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.Index
import javax.persistence.Table

/**
 * The family of schemas for [DidState].
 */
object DidSchema

/**
 * A [DidState] schema.
 * Value service can query with didExternalForm and retrieve the linerId of the corresponding state to check if did exist or not
 * Second option is to directly query the vault service with did.UUID since that is used as a linearID for DidState.
 */

@CordaSerializable
object DidStateSchemaV1 : MappedSchema(schemaFamily = DidSchema::class.java, version = 1, mappedTypes = listOf(PersistentDidState::class.java)) {
	@Entity
	@Table(name = "did_states", indexes = [Index(name = "did_external_form_idx", columnList = "did_external_form")])
	class PersistentDidState(
			@Column(name = "did_originator", nullable = false)
			var originator: Party,

			@Column(name = "did_external_form", nullable = false)
			var didExternalForm: String,

			@Column(name = "did_status", nullable = false)
			var status: DidStatus,

			@Column(name = "linear_id", nullable = false)
			var linearId: UUID) : PersistentState()
}