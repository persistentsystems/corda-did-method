package corda.net.did.resolver.registry

import corda.net.did.resolver.CordaDid
import org.http4k.core.Method.GET
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Uri
import java.io.InputStream

class IdentityNodeProxy(
        private val handler: (Request) -> Response,
        private val registry: IdentityNodeRegistry
) {

    /**
     * TODO Consider whether this should return a strongly typed result instead.
     *
     * For now, this can be a proxy that returns a format-agnostic result.
     */
    fun resolve(id: CordaDid): InputStream {
        registry.location().let { location ->
            val port = location.port ?: 80

            val response = handler(Request(
                    GET,
                    Uri.of("https://${location.host}:$port/1.0/identifiers/${id.toExternalForm()}")
            ))

            if (!response.status.successful)
                throw SourceException("Target server responded with ${response.status}")

            return response.body.stream
        }
    }
}

class SourceException(s: String) : Exception(s)