package net.corda.did.resolver

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import net.corda.did.resolver.CordaDid.Companion
import org.junit.Test
import java.util.UUID

class CordaDidTests {

    @Test
    fun `Can roundtrip a Corda DID`() {
        val internal = UUID.nameUUIDFromBytes(ByteArray(0))
        val initial = CordaDid(internal)
        val external = initial.toExternalForm()

        assertThat(external, equalTo("did:corda:d41d8cd9-8f00-3204-a980-0998ecf8427e"))

        val recovered = CordaDid.fromExternalForm(external)

        assertThat(recovered, equalTo(initial))
    }
}