package com.r3.sgx.rng.enclave

import com.r3.sgx.core.common.*
import com.r3.sgx.core.host.EnclaveHandle
import com.r3.sgx.core.host.EnclaveletHostHandler
import com.r3.sgx.core.host.EpidAttestationHostConfiguration
import com.r3.sgx.core.host.NativeHostApi
import com.r3.sgx.core.host.internal.Native
import com.r3.sgx.enclavelethost.client.Crypto
import com.r3.sgx.testing.BytesRecordingHandler
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.test.assertEquals

class RngEnclaveTest {
    // The SGX gradle plugin sets this property to the path of the built+signed enclave.
    private val enclaveFile = File(System.getProperty("com.r3.sgx.enclave.path"))

    private lateinit var enclave: EnclaveHandle<EnclaveletHostHandler.Connection>

    @Before
    fun setup() {
        // Configure the host side of attestation. You need to specify:
        // - Whether you want to produce linkable or unlinkable quotes
        // - Your SPID
        //
        // "Linkability" relates to the EPID provisioning protocol. This is a blind join protocol used to create the
        // attestation key that the Quoting Enclave will use to sign reports generated by your enclave. The protocol
        // ensures that when you send a signed quote to the Intel Attestation Service for verification, Intel won't be
        // able to identify which CPU produced the quote.
        // Furthermore if the quote is *unlinkable* then Intel (or anyone else) won't be able to tell whether two
        // separate quotes came from the same CPU.
        // *Linkable* quotes are still unidentifiable, but two such quotes coming from the same CPU may be correlated.
        // See https://software.intel.com/en-us/articles/signature-policy for further details.
        //
        // "SPID" is the Service Provider ID Intel provisions when you whitelist the Client TLS key you can use to talk
        // to the IAS using MutualTLS.
        // See https://software.intel.com/en-us/articles/certificate-requirements-for-intel-attestation-services for
        // further details.
        //
        // In this test we use dummy values as we are not doing a full attestation roundtrip.
        val attestationConfiguration = EpidAttestationHostConfiguration(
                quoteType = SgxQuoteType32.LINKABLE,
                spid = Cursor.allocate(SgxSpid)
        )

        // Create the enclave itself, setting up the host with EnclaveletHostHandler(), which mirrors RngEnclave's
        // handler tree.
        enclave = NativeHostApi.createEnclave(EnclaveletHostHandler(attestationConfiguration), enclaveFile, isDebug = true)
    }

    @After
    fun shutdown() {
        Native.destroyEnclave(enclave.enclaveId)
    }

    @Test
    fun rngEnclaveWorks() {
        // Create a quote, including the enclave's report data created by RngEnclave.createReportData and signed by the
        // Quoting Enclave. Note that this test by default uses a Simulation enclave so the signature is a dummy one.
        // Furthermore the test does *not* do a full attestation roundtrip to the Intel Attestation Service!
        //
        // To do such a roundtrip we need to use a Debug or a Release enclave. Furthermore we need a whitelisted TLS key
        // to talk to the IAS and verify such a quote, as explained above.
        //
        // Without doing the above roundtrip the enclave is *not* to be trusted! This test as it stands is for
        // demonstration purposes only. To see what happens with a Debug/Release enclave change the test{} block in
        // enclave/build.gradle to point to the appropriate enclave task.
        //
        // In the following we use [Cursor]s which are basically a JVM way of inspecting native SGX structs. They are
        // simply typed pointers to a region of an underlying byte blob.
        // A Cursor internally holds an offset into the blob, the size of the region, and an Encoder object describing
        // the layout of the region, which we can use to traverse the blob further down.
        val signedQuote:        Cursor<ByteBuffer, SgxSignedQuote> = enclave.connection.attestation.getQuote()
        val quote:              Cursor<ByteBuffer, SgxQuote>       = signedQuote[signedQuote.encoder.quote]
        val reportBodyInQuote:  Cursor<ByteBuffer, SgxReportBody>  = quote[SgxQuote.reportBody]

        // Get a view on the report data created by RngEnclave.createReportData
        val hashedEnclaveKey = reportBodyInQuote[SgxReportBody.reportData].read()

        // Check that the measurement matches the enclave's that we wanted to load
        // First read the metadata from the enclave file
        val metadata:              Cursor<ByteBuffer, SgxMetadata>    = NativeHostApi.readMetadata(enclaveFile)
        val cssBodyInMetadata:     Cursor<ByteBuffer, SgxCssBody>     = metadata[SgxMetadata.enclaveCss][SgxEnclaveCss.body]
        val measurementInMetadata: Cursor<ByteBuffer, SgxMeasurement> = cssBodyInMetadata[SgxCssBody.measurement]
        // Now get the measurement from the quote we created
        val measurementInQuote:    Cursor<ByteBuffer, SgxMeasurement> = reportBodyInQuote[SgxReportBody.measurement]
        assertEquals(measurementInMetadata, measurementInQuote)

        // Open a channel to the enclave and send a request for a random sequence of bytes of size 256. First create a
        // handler that records the binary blobs sent by the enclave.
        val handler = BytesRecordingHandler()
        // Now open the channel itself.
        val channel = enclave.connection.channels.addDownstream(0, handler)
        val message = ByteBuffer.allocate(4)
        val requestedRandomBytesSize = 256
        message.putInt(requestedRandomBytesSize)
        message.rewind()
        channel.send(message)

        // Get the enclave's OCALL reply from the handler. Note that the channel send is synchronous, the enclave will
        // reply in the same callchain. I.e. the execution stack at the time of the reply will look something like this:
        //
        // (stack growing down)
        // HOST:    rngEnclaveWorks    -- this test
        // HOST:    channel.send       -- the above send
        // HOST:    ecall_host_side    -- internals of send, which translates to an ECALL
        // =========================== -- host-enclave boundary
        // ENCLAVE: ecall_enclave_side -- internals of receive in the enclave
        // ENCLAVE: RngHandler.receive -- the receive function in RngHandler, generating/signing the random numbers
        // ENCLAVE: connection.send     -- the enclave is replying here
        // ENCLAVE: ocall_enclave_side -- internals of send, which translates to an OCALL
        // =========================== -- enclave-host boundary
        // HOST:    ocall_host_side    -- internals of receive in the host
        // HOST:    handler.receive    -- the receive function in the handler we created for the channel
        //
        // Therefore when the above send() returns we will have already received the reply, recorded in handler.ocalls.
        assertEquals(1, handler.ocalls.size)
        val responseBytes = handler.ocalls.first()
        val randomBytesSize = responseBytes.int
        assertEquals(requestedRandomBytesSize, randomBytesSize)
        val randomBytes = ByteArray(randomBytesSize)
        responseBytes.get(randomBytes)

        // Get the enclave's public key and check it against the hash in the report.
        val publicKeySize = responseBytes.int
        val publicKey = ByteArray(publicKeySize)
        responseBytes.get(publicKey)
        val keyDigest = MessageDigest.getInstance("SHA-512").digest(publicKey)
        assertEquals(hashedEnclaveKey, ByteBuffer.wrap(keyDigest))

        // Get the enclave's signature over the random bytes and check its correctness.
        val signatureSize = responseBytes.int
        val signature = ByteArray(signatureSize)
        responseBytes.get(signature)
        val signatureSchemeFactory = Crypto.getSignatureSchemeFactory(SecureRandom.getInstance("SHA1PRNG"))
        val eddsaScheme = signatureSchemeFactory.make(SchemesSettings.EDDSA_ED25519_SHA512)
        eddsaScheme.verify(
                publicKey = eddsaScheme.decodePublicKey(publicKey),
                signatureData = signature,
                clearData = randomBytes
        )

        // Close the channel.
        enclave.connection.channels.removeDownstream(0)
    }
}
