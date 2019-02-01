package corda.net.did.resolver

import corda.net.did.resolver.registry.IdentityNodeProxy
import corda.net.did.resolver.registry.SourceException
import org.http4k.core.HttpHandler
import org.http4k.core.Method.GET
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status.Companion.BAD_REQUEST
import org.http4k.core.Status.Companion.INTERNAL_SERVER_ERROR
import org.http4k.core.Status.Companion.OK
import org.http4k.routing.bind
import org.http4k.routing.path
import org.http4k.routing.routes

class ResolverApp(private val client: IdentityNodeProxy) : HttpHandler {
    private val routes = routes(
            "/1.0/identifiers/{did}" bind GET to fun(req: Request): Response {
                val did = req.path("did")!!.let {
                    try {
                        CordaDid.fromExternalForm(it)
                    } catch (e: IllegalArgumentException) {
                        return Response(BAD_REQUEST).body("Invalid ID provided")
                    }
                }

                val source = try {
                    client.resolve(did)
                } catch (e: SourceException) {
                    return Response(INTERNAL_SERVER_ERROR)
                }

                return source.use { stream ->
                    Response(OK)
                            .header("Content-Type", "application/json; charset=utf-8")
                            .body(stream)
                }
            }
    )

    override fun invoke(req: Request): Response = routes(req)
}
