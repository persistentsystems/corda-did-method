/**
 * R3 copy
 *
 */

package net.corda.did

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import com.natpryce.hamkrest.has
import com.natpryce.hamkrest.throws
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

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
		val actual = CordaDid(expected).toExternalForm()

		assertThat(actual, equalTo(expected))
	}

	@Test
	fun `rejects non-DIDs`() {
		assertThat({
			CordaDid("bogus:corda:$networkName:6f262985-38e9-4766-98b9-9dde14a38740")
		}, throws<IllegalArgumentException>(has(IllegalArgumentException::message, equalTo("""DID must use the "did" scheme. Found "bogus"."""))))
	}
}
