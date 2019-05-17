/**
 * R3 copy
 *
 */

package net.corda.did.resolver

import com.natpryce.konfig.ParseResult
import com.natpryce.konfig.PropertyType
import com.natpryce.konfig.propertyType
import net.corda.did.resolver.registry.IdentityNodeLocation

val identityNodeListType: PropertyType<List<IdentityNodeLocation>> = propertyType { line ->
	line.split(",").map { host ->
		host.trim().split(":", limit = 2)
	}.map {
		IdentityNodeLocation(it[0], it.getOrNull(1)?.toInt())
	}.let {
		ParseResult.Success(it)
	}
}
