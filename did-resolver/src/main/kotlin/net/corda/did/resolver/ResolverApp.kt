/**
 * R3 copy
 *
 */

package net.corda.did.resolver

import net.corda.did.resolver.registry.IdentityNodeProxy
import net.corda.did.resolver.registry.SourceException
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
import java.net.URI

class ResolverApp(private val client: IdentityNodeProxy) : HttpHandler {
	private val routes = routes(
			"/1.0/identifiers/{did}" bind GET to fun(req: Request): Response {
				val did = req.path("did")!!.let {
					try {
						URI.create(it)
					} catch (e: IllegalArgumentException) {
						return Response(BAD_REQUEST).body("Malformed DID provided")
					}
				}

				if (!did.toString().startsWith("did:corda"))
					return Response(BAD_REQUEST).body("Non-Corda DID provided ")

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
