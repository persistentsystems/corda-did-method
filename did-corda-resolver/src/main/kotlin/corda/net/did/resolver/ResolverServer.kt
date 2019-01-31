package corda.net.did.resolver

import org.http4k.server.Http4kServer
import org.http4k.server.Jetty
import org.http4k.server.asServer

class ResolverServer(port: Int) : Http4kServer by ResolverApp().asServer(Jetty(port)) {

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val port = args.firstOrNull()?.toIntOrNull() ?: 0
            ResolverServer(port).start()
        }
    }
}