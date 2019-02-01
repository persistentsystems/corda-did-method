package corda.net.did.resolver

import com.natpryce.hamkrest.assertion.assertThat
import corda.net.did.resolver.registry.IdentityNodeLocation
import corda.net.did.resolver.registry.IdentityNodeProxy
import corda.net.did.resolver.registry.StaticIdentityNodeRegistry
import org.http4k.core.ContentType.Companion.APPLICATION_JSON
import org.http4k.core.HttpHandler
import org.http4k.core.Method.GET
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status.Companion.BAD_REQUEST
import org.http4k.core.Status.Companion.INTERNAL_SERVER_ERROR
import org.http4k.core.Status.Companion.OK
import org.http4k.hamkrest.hasBody
import org.http4k.hamkrest.hasContentType
import org.http4k.hamkrest.hasStatus
import org.junit.Test

class ResolverAppTests {

    private val source: HttpHandler = { Response(OK).body("Lorem Ipsum Dolor") }

    private val proxy = IdentityNodeProxy(
            handler = source,
            registry = StaticIdentityNodeRegistry(setOf(IdentityNodeLocation("example.org", null)))
    )

    @Test
    fun `resolver will return proxied content for valid request`() {
        val app = ResolverApp(proxy)

        val actual = app(Request(GET, "http://proxy.local/1.0/identifiers/did:corda:e8bbf5c1-3d47-4287-9aa1-d74da32044a6"))

        assertThat(actual, hasStatus(OK))
        assertThat(actual, hasBody("Lorem Ipsum Dolor"))
        assertThat(actual, hasContentType(APPLICATION_JSON))
    }

    @Test
    fun `resolver will return error for invalid input DID`() {
        val app = ResolverApp(proxy)
        val actual = app(Request(GET, "http://proxy.local/1.0/identifiers/did:sov:2wJPyULfLLnYTEFYzByfUR"))

        assertThat(actual, hasStatus(BAD_REQUEST))
    }

    @Test
    fun `resolver will return error when source fails`() {
        val app = ResolverApp(IdentityNodeProxy(
                handler = { Response(INTERNAL_SERVER_ERROR).body("boom!") },
                registry = StaticIdentityNodeRegistry(setOf(IdentityNodeLocation("example.org", null)))
        ))

        val actual = app(Request(GET, "http://proxy.local/1.0/identifiers/did:corda:e8bbf5c1-3d47-4287-9aa1-d74da32044a6"))

        assertThat(actual, hasStatus(INTERNAL_SERVER_ERROR))
    }
}