package net.corda.did.api
/**
 * Persistent code
 *
 */
/**
 * @return returns the appropriate string message for the enum key
 * */
enum class APIMessage(val message: String) {

    NOT_FOUND( "The provided DID is not found." ),
    DID_DELETED( "The provided DID is no longer active." ),
    CONFLICT( "The provided DID already exists." ),
    DOCUMENT_EMPTY( "No document has been provided." ),
    INSTRUCTION_EMPTY( "No instruction has been provided." ),
    DID_EMPTY( "No DID has been provided." ),
    INVALID_SIGNATURE( "Signature is invalid." ),
    MALFORMED_INSTRUCTION( "Instruction provided is malformed." ),
    MALFORMED_DOCUMENT( "Document provided is malformed." ),
    PRECURSOR_DID( "The precursor DID is invalid." ),
    NO_PUBLIC_KEYS( "The document does not contain any public keys." ),
    MULTIPLE_SIGNATURES( "Multiple Signatures target the same key." ),
    MULTIPLE_PUBLIC_KEY( "Multiple public keys have the same ID." ),
    MISMATCH_SIGNATURE_TO_KEY_COUNT( "The number of keys in the DID document does not match the number of signatures." ),
    UNSUPPORTED_CRYPTO_SUITE( "Unsupported cryptographic suite." ),
    NO_SIGNATURE( "No signature was provided for target." ),
    CRYPTOSUITE_MISMATCH( "Signing key suite and signature are different." ),
    NO_MATCHING_SIGNATURE( "No signature is provided for any of the keys." ),
    MISSING_SIGNATURE( "Signature is missing for a target." ),
    MISSING_TEMPORAL_INFORMATION( "The document is missing information about its creation." ),
    INVALID_TEMPORAL_INFORMATION( "Document's temporal relation is incorrect." ),
    INVALID_PUBLIC_KEY( "PublicKey ID must contain did as prefix for target." ),
    INCORRECT_FORMAT( "The DID requested is not in the correct format." ),
    MISMATCH_DID ( "There is a mismatch in the DID provided in request parameter and one in document" )

}