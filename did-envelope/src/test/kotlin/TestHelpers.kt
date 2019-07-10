package net.corda

import com.natpryce.Failure
import com.natpryce.Result
import com.natpryce.Success
import junit.framework.AssertionFailedError

fun <T, E> Result<T, E>.assertSuccess(): T = when (this) {
	is Success -> this.value
	is Failure -> throw AssertionFailedError("Expected result to be a success but it failed: ${this.reason}")
}

fun <T, E> Result<T, E>.assertFailure(): E = when (this) {
	is Success -> throw AssertionFailedError("Expected result to be a failure but was a success")
	is Failure -> this.reason
}
