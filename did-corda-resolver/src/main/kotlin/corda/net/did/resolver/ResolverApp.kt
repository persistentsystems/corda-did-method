package corda.net.did.resolver

import corda.net.did.resolver.registry.IdentityNodeClient
import org.http4k.core.HttpHandler
import org.http4k.core.Method.GET
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status.Companion.BAD_REQUEST
import org.http4k.core.Status.Companion.OK
import org.http4k.routing.bind
import org.http4k.routing.path
import org.http4k.routing.routes

class ResolverApp(private val client: IdentityNodeClient) : HttpHandler {
    private val routes = routes(
        "/1.0/identifiers/{did}" bind GET to fun(req: Request): Response {
            val did = req.path("did")!!.let {
                try {
                    CordaDid.fromExternalForm(it)
                } catch (e: Exception) {
                    return Response(BAD_REQUEST).body("Invalid ID provided")
                }
            }

            return Response(OK).body("Resolve $did now!")
        }
    )

    override fun invoke(req: Request): Response = routes(req)
}
