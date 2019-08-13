package com.r3.sgx.rng.enclave

import com.r3.sgx.core.common.attestation.AttestedSignatureVerifier
import com.r3.sgx.core.common.attestation.PublicKeyAttester
import com.r3.sgx.core.common.crypto.SignatureSchemeId
import com.r3.sgx.enclavelethost.client.EpidAttestationVerificationBuilder
import com.r3.sgx.rng.client.common.RngEnclaveletHostClient
import com.r3.sgx.testing.MockAttestationCertStore
import org.junit.BeforeClass
import org.junit.Test
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.*

class RngEnclaveClientTest {
    companion object {
        private val logger: Logger = LoggerFactory.getLogger(RngEnclaveClientTest::class.java)
        private val grpcPort: Int = getIntegerProperty("com.r3.sgx.enclave.simulated.grpc.port")

        @BeforeClass
        @JvmStatic
        fun setup() {
            logger.info("RNG Host: port={}", grpcPort)
        }

        private fun getIntegerProperty(name: String): Int
            = Integer.getInteger(name) ?: fail("System property '$name' not set")

        private fun fail(message: String): Nothing = throw AssertionError(message)
    }

    @Test
    fun testHost() {
        RngEnclaveletHostClient.withClient("localhost:$grpcPort") { client ->
            val rngResponse = client.getRandomBytes()
            val attestation = client.getAttestation().attestation!!
            val attestationVerifier = EpidAttestationVerificationBuilder()
                    .withAcceptDebug(true)
                    .build()
            val attestedQuote = attestationVerifier.verify(MockAttestationCertStore.loadTestPkix(), attestation)
            val keyAuthenticator = PublicKeyAttester(attestedQuote)
            val enclaveSignatureVerifier = AttestedSignatureVerifier(
                    SignatureSchemeId.EDDSA_ED25519_SHA512,
                    keyAuthenticator)
            enclaveSignatureVerifier.verify(
                enclaveSignatureVerifier.decodeAttestedKey(rngResponse.publicKey),
                rngResponse.signature,
                rngResponse.randomBytes
            )
            val base64RandomBytes = Base64.getEncoder().encode(rngResponse.randomBytes)
            logger.info("RandomBytes={}", String(base64RandomBytes))
        }
    }
}