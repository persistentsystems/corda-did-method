package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import com.natpryce.hamkrest.has
import com.natpryce.hamkrest.throws
import org.junit.Test

@Suppress("RemoveExplicitTypeArguments")
class CordaDidTests {

	@Test
	fun `can roundtrip Corda DID`() {
		val expected = "did:corda:tcn:6f262985-38e9-4766-98b9-9dde14a38740"
		val actual = CordaDid.fromExternalForm(expected).toExternalForm()

		assertThat(actual, equalTo(expected))
	}

	@Test
	fun `can generate URI`() {
		val example = CordaDid.fromExternalForm("did:corda:tcn:6f262985-38e9-4766-98b9-9dde14a38740").toURI()

		assertThat(example.scheme, equalTo("did"))
		assertThat(example.schemeSpecificPart, equalTo("corda:tcn:6f262985-38e9-4766-98b9-9dde14a38740"))
	}

	@Test
	fun `rejects DID with unsupported method`() {
		assertThat({
			CordaDid.fromExternalForm("did:bogus:tcn:6f262985-38e9-4766-98b9-9dde14a38740")
		}, throws<IllegalArgumentException>(has(IllegalArgumentException::message, equalTo("""Invalid method "bogus" provided"""))))
	}

	@Test
	fun `rejects DID with unsupported realm`() {
		assertThat({
			CordaDid.fromExternalForm("did:corda:xxx:6f262985-38e9-4766-98b9-9dde14a38740")
		}, throws<IllegalArgumentException>(has(IllegalArgumentException::message, equalTo("""Invalid realm "xxx" provided"""))))
	}

	@Test
	fun `rejects non-UUID DID`() {
		assertThat({
			CordaDid.fromExternalForm("did:corda:tcn:123456789")
		}, throws<IllegalArgumentException>(has(IllegalArgumentException::message, equalTo("""Invalid UUID string: 123456789"""))))
	}
}