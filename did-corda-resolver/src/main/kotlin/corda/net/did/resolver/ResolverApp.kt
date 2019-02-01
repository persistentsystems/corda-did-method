package corda.net.did.resolver

import corda.net.did.resolver.registry.IdentityNodeRegistry
import org.http4k.core.HttpHandler
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status.Companion.OK

class ResolverApp(private val registry: IdentityNodeRegistry) : HttpHandler {
    override fun invoke(req: Request): Response = Response(OK).body("Hello World. Resolve ID from " + registry.location())
}
