package corda.net.did.resolver

import com.natpryce.konfig.*
import corda.net.did.resolver.registry.IdentityNodeClient
import corda.net.did.resolver.registry.StaticNodeRegistry
import org.http4k.client.OkHttp
import org.http4k.server.Http4kServer
import org.http4k.server.Jetty
import org.http4k.server.asServer

class ResolverServer(client: IdentityNodeClient, port: Int?) :
    Http4kServer by ResolverApp(client).asServer(Jetty(port ?: 0)) {

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val config = EnvironmentVariables() overriding ConfigurationProperties.fromResource("defaults.properties")

            val port = config.getOrNull(Key("port", intType))
            val registry = StaticNodeRegistry(config[Key("nodes", identityNodeListType)].toSet())
            val client = IdentityNodeClient(OkHttp(), registry)

            ResolverServer(client, port).start()
        }
    }
}