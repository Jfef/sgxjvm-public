package com.r3.sgx.rng.client

import com.r3.sgx.core.common.attestation.*
import com.r3.sgx.core.common.crypto.SignatureSchemeId
import com.r3.sgx.rng.client.common.RngEnclaveletHostClient
import picocli.CommandLine
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.util.*
import java.util.concurrent.Callable

@CommandLine.Command(
        name = "get-random",
        description = ["Retrieve random numbers"],
        mixinStandardHelpOptions = true
)
class GetRandomCommand : VerifyingCommand(), Callable<Unit> {
    @CommandLine.Parameters(
            index = "0",
            description = ["The address of the RNG enclavelet host"]
    )
    var hostAddress: String = "localhost:8080"

    override fun call() {
        RngEnclaveletHostClient.withClient(hostAddress) { client ->
            val attestation = client.getAttestation().attestation
            val quote = verifyAttestation(attestation)
            val rngResponse = client.getRandomBytes()
            val keyHash = MessageDigest.getInstance("SHA-512").digest(rngResponse.publicKey)
            val keyHashInReport = SgxQuoteReader(quote.data).reportData
            if (ByteBuffer.wrap(keyHash) != keyHashInReport) {
                throw GeneralSecurityException("Key hash in attestation report doesn't match the hash of the claimed enclave key")
            }

            val keyAuthenticator = PublicKeyAttester(quote)
            val enclaveSignatureVerifier = AttestedSignatureVerifier(
                    SignatureSchemeId.EDDSA_ED25519_SHA512,
                    keyAuthenticator)
            enclaveSignatureVerifier.verify(
                    enclaveSignatureVerifier.decodeAttestedKey(rngResponse.publicKey),
                    rngResponse.signature,
                    rngResponse.randomBytes
            )
            val base64RandomBytes = Base64.getEncoder().encode(rngResponse.randomBytes)
            print(String(base64RandomBytes))
        }
    }
}