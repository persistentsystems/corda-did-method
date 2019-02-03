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
				criteria = equalTo(Did("did:example:123456789abcdefghi").toExternalForm())
		)
	}
}