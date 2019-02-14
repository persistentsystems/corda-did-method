package net.corda.did.resolver

import java.net.URI
import java.util.UUID

fun UUID.toCordaDid(): URI = URI("did:corda:tcn:" + this)