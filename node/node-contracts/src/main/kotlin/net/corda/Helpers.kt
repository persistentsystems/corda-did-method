package net.corda

import com.grack.nanojson.JsonObject

fun JsonObject.getArrayOfObjects(key: String) = getArray(key).filterIsInstance(JsonObject::class.java)
