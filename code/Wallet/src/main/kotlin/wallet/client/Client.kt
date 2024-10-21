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

import wallet.signatures.*
import java.math.BigInteger
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    if (args.isEmpty() || args.size < 2) {
        println("""
            Usage: wallet.client.ClientKt    keyGen           <client id> <index key id> <schnorr | bls | symmetric>
                                             sign             <client id> <index key id> <schnorr | bls> <data>
                                             enc              <client id> <index key id> <data>
                                             dec              <client id> <index key id> <ciphertext>
                                             getPk            <client id> <index key id> <schnorr | bls>
                                             valSign          <client id> <signature> <initial data>
                                             availableKeys    <client id>
                                             help
        """.trimIndent())
        exitProcess(-1)
    }
    val operation = args[0]
    val clientId = args[1].toInt()

    val clientAPI = ClientAPI(clientId)
    when (operation) {
        "keyGen" -> {
            val indexId = args[2]
            val signatureScheme = stringToSignatureScheme(args[3])
            val isSuccess = clientAPI.generateKey(indexId, signatureScheme)
            println("Key generation: ${if (isSuccess) "successful" else "failed"}")
        }
        "sign" -> {
            val indexId = args[2]
            val signatureScheme = stringToSignatureScheme(args[3])
            val data = args[4].toByteArray()
            val signature = clientAPI.signData(indexId, signatureScheme, data)
            println("$signatureScheme signature: ${BigInteger(signature).toString(16)}\n")
        }
        "enc" -> {
            val indexId = args[2]
            val data = args[3].toByteArray()
            val ciphertext = clientAPI.encryptData(indexId, data)
            println("Encrypted message: ${BigInteger(ciphertext).toString(16)}\n")
        }
        "dec" -> {
            val indexId = args[2]
            val ciphertext = BigInteger(args[3], 16).toByteArray()
            val plainData = clientAPI.decryptData(indexId, ciphertext)
            println("Decrypted message: ${plainData?.decodeToString()}\n")
        }
        "valSign" -> {
            val signature = BigInteger(args[2], 16)
            val initialData = args[3].toByteArray()
            val validity = clientAPI.validateSignature(signature.toByteArray(), initialData)
            println("The signature is ${if (validity) "valid" else "invalid"}.\n")
        }
        "getPk" -> {
            val indexId = args[2]
            val signatureScheme = stringToSignatureScheme(args[3])
            val pk = clientAPI.getPublicKey(indexId, signatureScheme)
            println("$signatureScheme signing public key: ${BigInteger(pk).toString(16)}\n")
        }
        "availableKeys" -> clientAPI.availableKeys()
        "help" -> clientAPI.commands()
        else -> println("Operation not found: $operation")
    }

    clientAPI.close()
}
