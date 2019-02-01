package net.corda.did.resolver.registry

import com.natpryce.hamkrest.assertion.assertThat
import com.natpryce.hamkrest.equalTo
import com.natpryce.hamkrest.hasSize
import net.corda.did.resolver.CordaDid
import org.http4k.core.HttpHandler
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status.Companion.OK
import org.http4k.hamkrest.hasUri
import org.junit.Test
import java.io.BufferedReader
import java.util.UUID

class IdentityNodeProxyTests {
    private var requests: MutableList<Request> = mutableListOf()

    private val spyHandler: HttpHandler = { req ->
        requests.add(req)
        Response(OK)
    }

    @Test
    fun `the path is resolved correctly`() {
        val proxy = IdentityNodeProxy(
                handler = spyHandler,
                registry = StaticIdentityNodeRegistry(setOf(IdentityNodeLocation("example.org", 7777)))
        )

        proxy.resolve(CordaDid(UUID.nameUUIDFromBytes(ByteArray(0))))

        assertThat(requests, hasSize(equalTo(1)))

        assertThat(
                requests.single(),
                hasUri("https://example.org:7777/1.0/identifiers/did:corda:d41d8cd9-8f00-3204-a980-0998ecf8427e")
        )
    }

    @Test
    fun `the payload the proxy returns reflects the source`() {
        val expected = "foo bar baz"

        val bogusHandler: HttpHandler = { Response(OK).body(expected) }

        val proxy = IdentityNodeProxy(
                handler = bogusHandler,
                registry = StaticIdentityNodeRegistry(setOf(IdentityNodeLocation("example.org", 7777)))
        )

        val result = proxy
                .resolve(CordaDid(UUID.nameUUIDFromBytes(ByteArray(0))))
                .bufferedReader()
                .use(BufferedReader::readText)

        assertThat(result, equalTo(expected))
    }
}