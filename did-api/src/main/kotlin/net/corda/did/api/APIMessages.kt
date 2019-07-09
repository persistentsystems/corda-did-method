package net.corda.did.api
/**
 * Enum for API  messages
 * */
/**
 * Persistent code
 *
 */
/**
 * @param [message] The response message as a string
 * @return The appropriate string message for the enum key
 * */
enum class APIMessage(val message: String) {
   /** Error message if the DID is not found*/
    NOT_FOUND( "The provided DID is not found." ),
    /** Error message if DID is deleted*/
    DID_DELETED( "The provided DID is no longer active." ),
    /** Error message if the provided DID already exists*/
    CONFLICT( "The provided DID already exists." ),
    /** Error message if document is empty*/
    DOCUMENT_EMPTY( "No document has been provided." ),
    /** Error message if instruction is empty*/
    INSTRUCTION_EMPTY( "No instruction has been provided." ),
    /** Error message if DID is not provided*/
    DID_EMPTY( "No DID has been provided." ),
    /** Error message if signature is invalid*/
    INVALID_SIGNATURE( "Signature is invalid." ),
    /** Error message if instruction is malformed*/
    MALFORMED_INSTRUCTION( "Instruction provided is malformed." ),
    /** Error message if document is malformed*/
    MALFORMED_DOCUMENT( "Document provided is malformed." ),
    /** Error message if precursor DID provided is incorrect or invalid*/
    PRECURSOR_DID( "The precursor DID is invalid." ),
    /** Error message if document has no public keys*/
    NO_PUBLIC_KEYS( "The document does not contain any public keys." ),
    /** Error message if multiple signatures have the same key as target*/
    MULTIPLE_SIGNATURES( "Multiple Signatures target the same key." ),
    /** Error message if document has multiple public keys with same id*/
    MULTIPLE_PUBLIC_KEY( "Multiple public keys have the same ID." ),
    /** Error message if instruction has incorrect number of signatures to public keys*/
    MISMATCH_SIGNATURE_TO_KEY_COUNT( "The number of keys in the DID document does not match the number of signatures." ),
    /** Error message if an unsupported cryptographic suite is used*/
    UNSUPPORTED_CRYPTO_SUITE( "Unsupported cryptographic suite." ),
    /** Error message if no signature is provided in the instruction*/
    NO_SIGNATURE( "No signature was provided for target." ),
    /** Error message if signature are signed with different suite from the keys provided*/
    CRYPTOSUITE_MISMATCH( "Signing key suite and signature are different." ),
    /** Error message if no signature is provided for any of the keys*/
    NO_MATCHING_SIGNATURE( "No signature is provided for any of the keys." ),
    /** Error message if instruction is missing a signature for the target*/
    MISSING_SIGNATURE( "Signature is missing for a target." ),
    /** Error message if document is missing created or updated field*/
    MISSING_TEMPORAL_INFORMATION( "The document is missing information about its creation." ),
    /** Error message if document created or updated date is invalid*/
    INVALID_TEMPORAL_INFORMATION( "Document's temporal relation is incorrect." ),
    /** Error message if document if public key id does not have a prefix for the target*/
    INVALID_PUBLIC_KEY( "PublicKey ID must contain did as prefix for target." ),
    /** Error message if DID is not in correct format*/
    INCORRECT_FORMAT( "The DID requested is not in the correct format." ),
    /** Error message if DID provided as request parameter is different from the one in document body*/
    MISMATCH_DID ( "There is a mismatch in the DID provided in request parameter and one in document" )

}