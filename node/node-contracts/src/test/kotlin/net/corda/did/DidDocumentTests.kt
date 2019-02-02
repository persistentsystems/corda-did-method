package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import net.corda.did.SpecExamples.`Minimal self-managed DID Document`
import org.junit.Test
import java.util.UUID

class DidDocumentTests {

	@Test
	fun `ID can be extracted from a DID document`() {
		val example = DidDocument(`Minimal self-managed DID Document`)

		assertThat(example.id(), equalTo(CordaDid(Realm.CordaNetwork, UUID.fromString("d1c9ae4e-130c-49d7-af0c-b2d626c13afc"))))
	}
}