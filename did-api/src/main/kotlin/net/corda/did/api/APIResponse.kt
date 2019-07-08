package net.corda.did.api

/**
 * Persistent code
 *
 */
/**
 * @param[message] takes a string message input
 * @return a proper message object which can then be sent as response
 * */
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
//pranav 2019-06-27 removed as per comment
