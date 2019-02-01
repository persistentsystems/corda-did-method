package corda.net.did.resolver.registry

import corda.net.did.resolver.CordaDid
import org.http4k.core.Method.GET
import org.http4k.core.Request
import org.http4k.core.Response
import java.net.URI

class IdentityNodeClient(
    private val handler: (Request) -> Response,
    private val registry: IdentityNodeRegistry
) {

    /**
     * TODO Consider whether this should return a strongly typed result instead.
     * For now, this can be a proxy that returns a format-agnostic result.
     */
    fun resolve(id: CordaDid): String {
        registry.location().let { location ->
            val target = URI(
                "https",
                "",
                location.host,
                location.port ?: 80,
                "foo/bar/baz/${id.toExternalForm()}",
                "",
                ""
            )

            return handler(Request(GET, target.toASCIIString())).bodyString()
        }
    }
}