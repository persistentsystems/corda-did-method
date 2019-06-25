package net.corda.did.api

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
// ??? moritzplatt 2019-06-20 -- what purpose has this method? seems to do a `copy`?
