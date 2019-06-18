package net.corda.did.api

import net.corda.did.state.DidState
/**
 * Persistent code
 *
 */
data class ApiResponse(val message:String?){
    constructor(apiMessage:APIMessage) : this(apiMessage.message) {

    }
}

fun ApiResponse.toResponseObj(): ApiResponse {

    return ApiResponse (
            message.toString()
    )
}

fun DidState.toResponseObj():DidState{

    return DidState(
        envelope,
        originator,
        witnesses,
        status,
        linearId,
        participants

    )
}