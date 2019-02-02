package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import net.corda.did.SpecExamples.`Minimal self-managed DID Document`
import org.junit.Test

class DidDocumentTests {

	@Test
	fun `ID can be extracted from a DID document`() {
		val example = DidDocument(`Minimal self-managed DID Document`)

		assertThat(
				actual = example.id().toExternalForm(),
				criteria = equalTo(Did("did:corda:tcn:d1c9ae4e-130c-49d7-af0c-b2d626c13afc").toExternalForm())
		)
	}
}