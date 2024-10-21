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

package wallet.signatures.bls

import wallet.signatures.KeyPair
import java.math.BigInteger


class BlsSignatureScheme(threshold: Int) {
    private external fun initialize(threshold: Int)
    private external fun getOrderBytes(): ByteArray
    private external fun computeKeyPair(): Array<ByteArray>
    private external fun computePublicKey(privateKey: ByteArray): ByteArray
    private external fun computeSignature(privateKey: ByteArray, message: ByteArray): ByteArray
    private external fun computeVerification(signature: ByteArray, message: ByteArray, publicKey: ByteArray): Boolean
    private external fun interpolatePartialSignatures(vararg partialSignatures: Array<ByteArray>): ByteArray
    private external fun interpolatePartialPublicKeys(vararg partialPublicKeys: Array<ByteArray>): ByteArray

    private val order: BigInteger
    private val minThreshold = threshold + 2

    init {
        System.loadLibrary("Pairing")
        initialize(threshold)
        this.order = BigInteger(1, getOrderBytes())
    }

    fun getOrder(): BigInteger {
        return order
    }

    fun genKeyPair(): KeyPair {
        val keys = computeKeyPair()
        return KeyPair(keys[0], keys[1])
    }

    fun genKeyPair(privateKey: BigInteger): KeyPair {
        val publicKey = computePublicKey(privateKey.toByteArray())
        return KeyPair(privateKey.toByteArray(), publicKey)
    }

    fun computePublicKey(privateKey: BigInteger): ByteArray {
        return computePublicKey(privateKey.toByteArray())
    }

    fun sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        return computeSignature(privateKey, message)
    }

    fun verifySignature(signature: ByteArray, message: ByteArray, publicKey: ByteArray): Boolean {
        return computeVerification(signature, message, publicKey)
    }

    fun combinePartialSignatures(
        partialSignatures: Map<BigInteger, ByteArray>,
        partialPublicKeys: Map<BigInteger, ByteArray>,
        message: ByteArray,
    ): ByteArray {
        val validPartialSignatures = partialSignatures.filter { partialSignature ->
            verifySignature(partialSignature.value, message, partialPublicKeys[partialSignature.key]!!)
        }
        val serializedPartialSignatures = serializePartialData(validPartialSignatures)
        return interpolatePartialSignatures(*serializedPartialSignatures)
    }

    fun combinePartialPublicKeys(partialPublicKeys: Map<BigInteger, ByteArray>): ByteArray {
        val serializedPartialPublicKeys = serializePartialData(partialPublicKeys)

        return interpolatePartialPublicKeys(*serializedPartialPublicKeys)
    }

    companion object {
        private fun serializePartialData(partialData: Map<BigInteger, ByteArray>): Array<Array<ByteArray>> {
            val serializedPartialData: ArrayList<Array<ByteArray>> = ArrayList(partialData.size)
            var i = 0
            for ((key, value) in partialData) {
                val data = arrayOf<ByteArray>(key.toByteArray(), value)
                serializedPartialData.add(i++, data)
            }
            return serializedPartialData.toTypedArray()
        }
    }
}