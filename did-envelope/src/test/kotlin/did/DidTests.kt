package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import com.natpryce.hamkrest.isA
import net.corda.assertFailure
import net.corda.assertSuccess
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

/**
 * Test cases for [CordaDid]
 */
@Suppress("RemoveExplicitTypeArguments")
@RunWith(Parameterized::class)
class DidTests(
		private var networkName: String
) {

	companion object {
		@JvmStatic
		@Parameterized.Parameters
		fun errorCode() = listOf("tcn", "tcn-uat", "testnet")
	}

	@Test
	fun `can roundtrip DID`() {
		val expected = "did:corda:$networkName:6f262985-38e9-4766-98b9-9dde14a38740"
		val actual = CordaDid.parseExternalForm(expected).assertSuccess().toExternalForm()

		assertThat(actual, equalTo(expected))
	}

	@Test
	fun `rejects non-DIDs`() {
		val actual = CordaDid.parseExternalForm("bogus:corda:$networkName:6f262985-38e9-4766-98b9-9dde14a38740").assertFailure()
		@Suppress("RemoveExplicitTypeArguments")
		assertThat(actual, isA<CordaDidFailure.CordaDidValidationFailure.InvalidDidSchemeFailure>())
	}
}
