/*
 * CBFT-Wallet - a Confidential Byzantine Fault-Tolerant Wallet
 * Copyright (c) 2024 CBFT-Wallet Authors
 *
 * This file is part of CBFT-Wallet. CBFT-Wallet is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * CBFT-Wallet is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * CBFT-Wallet is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

package wallet.client

import kotlinx.coroutines.*
import wallet.signatures.KeyScheme
import wallet.signatures.stringToSignatureScheme
import java.math.BigInteger
import java.util.concurrent.CountDownLatch
import kotlin.math.pow
import kotlin.math.sqrt
import kotlin.system.exitProcess
import kotlin.system.measureTimeMillis

// Not working with multiple clients because of a problem in the implementation of many elliptic curves on COBRA
fun main(args: Array<String>) {
    if (args.isEmpty() || args.size < 2) {
        println("""Usage: wallet.client.ThroughputLatencyEvaluationKt  keyGen    <initial client id> <number of clients> <number of reps> <index key id> <schnorr | bls | symmetric>
                                                                    sign      <initial client id> <number of clients> <number of reps> <index key id> <schnorr or bls> <data>
                                                                    encDec    <initial client id> <number of clients> <number of reps> <index key id> <data>
                                                                    all       <initial client id> <number of clients> <number of reps>
        """.trimIndent())
        exitProcess(-1)
    }

    val operation = args[0]
    val initialClientId = args[1].toInt()
    val numClients = args[2].toInt()
    val numOperationsPerClient = args[3].toInt()

    val latch = CountDownLatch(numClients)

    // Single client test
    if (numClients == 1) {
        ClientHelperCoroutines(initialClientId, operation, numOperationsPerClient, args).singleTest()
        return
    }

    // Multi client test
    for (i in 0..<numClients) {
        ClientHelperThreads(initialClientId + i, latch, operation, numOperationsPerClient, args).start()
        Thread.sleep(10L)
    }

    latch.await()

/*    runBlocking {
        coroutineScope {
            for (i in 0..<numClients) {
                launch {
                    ClientHelperCoroutines(initialClientId + i, operationId, numOperationsPerClient, args).run()
                }
                println("Launched: ${initialClientId + i}")
//            delay(10L)
            }
        }
    }*/

    println("* Evaluation completed!")
}

private fun operationTests(threadId: Long, operation: String, times: Int, api: ClientAPI, args: Array<String>) {
    println("* Testing $operation in thread $threadId: STARTING")
    val executionTimes = DoubleArray(times)
    repeat(times) {
        val millis = measureTimeMillis {
            when (operation) {
                "all" -> testAllFunctionalities(it, api)
                "keyGen" -> api.generateKey("${args[4]}$it", stringToSignatureScheme(args[5]))
                "sign" -> {
                    val indexId = args[4]
                    val scheme = stringToSignatureScheme(args[5])
                    api.generateKey(indexId, scheme)
                    api.signData(indexId, scheme, args[6].toByteArray())
                }
                "encDec" -> {
                    val indexId = args[4]
                    val ciphertext = api.encryptData(indexId, args[5].toByteArray())
                    api.decryptData(indexId, ciphertext!!)
                }
            }
        }
        executionTimes[it] = millis.toDouble()
        println("$it:\t${millis / 1000.0} s")
    }
    println("* Testing $operation in thread $threadId: DONE\n")
    printStats(executionTimes)
}

private class ClientHelperThreads(
    clientId: Int,
    private val latch: CountDownLatch,
    private val operation: String,
    private val numOperations: Int,
    private val args: Array<String>,
): Thread() {
    val clientAPI = ClientAPI(clientId)

    override fun run() {
        try {
            latch.countDown()
            operationTests(this.id, operation, numOperations, clientAPI, args)
        } finally {
            clientAPI.close()
        }
    }
}

private class ClientHelperCoroutines(
    clientId: Int,
    private val operation: String,
    private val numOperations: Int,
    private val args: Array<String>,
){
    val clientAPI = ClientAPI(clientId)

    suspend fun run() = coroutineScope {
        try {
            operationTests(Thread.currentThread().id, operation, numOperations, clientAPI, args)
        } finally {
            clientAPI.close()
        }
    }

    fun singleTest() {
        operationTests(Thread.currentThread().id, operation, numOperations, clientAPI, args)
        clientAPI.close()
    }
}

private fun testAllFunctionalities(iteration: Int, api: ClientAPI) {
    // Generates a Schnorr signing key (private key & public key)
    val schnorrPrivateKeyId = "schnorr$iteration"
    val successSchnorr = api.generateKey(schnorrPrivateKeyId, KeyScheme.SCHNORR)
    println("Schnorr key generation: ${if (successSchnorr) "successful" else "failed"}")

    // Generates a BLS signing key (private key & public key)
    val blsPrivateKeyId = "bls$iteration"
    val successBls = api.generateKey(blsPrivateKeyId, KeyScheme.BLS)
    println("BLS key generation: ${if (successBls) "successful" else "failed"}")

    // Generates a symmetric key (for the encryption/decryption operation)
    val symmetricKeyId = "symmetric$iteration"
    val successSymmetric = api.generateKey(symmetricKeyId, KeyScheme.SYMMETRIC)
    println("Symmetric key generation: ${if (successSymmetric) "successful" else "failed"}")

    // Sign a message (Schnorr signature)
    val schnorrDataToSign = "SchnorrSignatureTest".toByteArray()
    val schnorrSignature = api.signData(schnorrPrivateKeyId, KeyScheme.SCHNORR, schnorrDataToSign)
    println("Schnorr signature: ${BigInteger(schnorrSignature).toString(16)}\n")

    val publicKeySchnorr = api.getPublicKey(schnorrPrivateKeyId, KeyScheme.SCHNORR)
    println("Schnorr signing public key: ${BigInteger(publicKeySchnorr).toString(16)}\n")

    val schnorrValidity = api.validateSignature(schnorrSignature, schnorrDataToSign)
    println("The Schnorr signature is ${if (schnorrValidity) "valid" else "invalid"}.\n")

    // Sign a message (BLS signature)
    val blsDataToSign = "BLSSignatureTest".toByteArray()
    val blsSignature = api.signData(blsPrivateKeyId, KeyScheme.BLS, blsDataToSign)
    println("BLS signature: ${BigInteger(blsSignature).toString(16)}\n")

    val publicKeyBls = api.getPublicKey(blsPrivateKeyId, KeyScheme.BLS)
    println("BLS signing public key: ${BigInteger(publicKeyBls).toString(16)}\n")

    val blsValidity = api.validateSignature(blsSignature, blsDataToSign)
    println("The BLS signature is ${if (blsValidity) "valid" else "invalid"}.\n")


    // Encryption
    val messageToEncrypt = "This is data to be encrypted"
    val ciphertext = api.encryptData(symmetricKeyId, messageToEncrypt.toByteArray())
    println("Ciphertext: ${BigInteger(ciphertext).toString(16)}")

    val plainData = api.decryptData(symmetricKeyId, ciphertext!!)
    println("Decrypted message: \"${plainData?.decodeToString()}\"")
}

private fun printStats(executionTimes: DoubleArray) {
    val results = executionTimes.drop((executionTimes.size * 0.1).toInt()).toDoubleArray()

    println("+ Mean: ${results.average()} ms")
    println("+ Standard Deviation: ${standardDeviation(results)}")
    println("+ Operations per second: ${(results.sum()/1000.0) / executionTimes.size}")
}

private fun standardDeviation(numbers: DoubleArray): Double {
    val mean = numbers.average()
    val variance = numbers.map { (it - mean).pow(2) }.average()
    return sqrt(variance)
}