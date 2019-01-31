package corda.net.did.resolver

import org.http4k.core.HttpHandler
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status.Companion.OK

class ResolverApp : HttpHandler {
    override fun invoke(req: Request): Response = Response(OK).body("Hello World")
}
