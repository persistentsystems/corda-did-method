package corda.net.did.resolver

import com.natpryce.konfig.ConfigurationProperties
import com.natpryce.konfig.EnvironmentVariables
import com.natpryce.konfig.Key
import com.natpryce.konfig.intType
import com.natpryce.konfig.overriding
import corda.net.did.resolver.registry.IdentityNodeRegistry
import corda.net.did.resolver.registry.StaticNodeRegistry
import org.http4k.server.Http4kServer
import org.http4k.server.Jetty
import org.http4k.server.asServer

class ResolverServer(registry: IdentityNodeRegistry, port: Int?) :
        Http4kServer by ResolverApp(registry).asServer(Jetty(port ?: 0)) {

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val config = EnvironmentVariables() overriding ConfigurationProperties.fromResource("defaults.properties")

            val port = config.getOrNull(Key("port", intType))
            val registry = StaticNodeRegistry(config[Key("nodes", identityNodeListType)].toSet())

            ResolverServer(registry, port).start()
        }
    }
}