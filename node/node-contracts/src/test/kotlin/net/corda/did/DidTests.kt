package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import com.natpryce.hamkrest.has
import com.natpryce.hamkrest.throws
import org.junit.Test

@Suppress("RemoveExplicitTypeArguments")
class DidTests {

	@Test
	fun `can roundtrip DID`() {
		val expected = "did:corda:tcn:6f262985-38e9-4766-98b9-9dde14a38740"
		val actual = Did(expected).toExternalForm()

		assertThat(actual, equalTo(expected))
	}

	@Test
	fun `rejects non-DIDs`() {
		assertThat({
			Did("bogus:corda:tcn:6f262985-38e9-4766-98b9-9dde14a38740")
		}, throws<IllegalArgumentException>(has(IllegalArgumentException::message, equalTo("""DID must use the "did" scheme. Found "bogus"."""))))
	}
}