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

package wallet.signatures.schnorr

import confidential.client.ConfidentialServiceProxy
import wallet.client.UncombinedConfidentialResponse
import wallet.communications.readByteArray
import wallet.communications.writeByteArray
import wallet.signatures.KeyScheme
import org.bouncycastle.math.ec.ECPoint
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import java.io.*
import java.math.BigInteger
import java.util.*
import kotlin.system.exitProcess

class SchnorrSignature(
    private var sigma: ByteArray,
    private var signingPublicKey: ByteArray,
    private var randomPublicKey: ByteArray
) : Externalizable {

    // Identifier used to identify the corresponding signature scheme when deserializing a signature
    private val id = KeyScheme.SCHNORR.ordinal

    fun getSigma() = sigma

    fun getSigningPublicKey() = signingPublicKey

    fun getRandomPublicKey() = randomPublicKey

    override fun writeExternal(out: ObjectOutput) {
        writeByteArray(out, sigma)
        writeByteArray(out, signingPublicKey)
        writeByteArray(out, randomPublicKey)
    }

    override fun readExternal(`in`: ObjectInput) {
        sigma = readByteArray(`in`)
        signingPublicKey = readByteArray(`in`)
        randomPublicKey = readByteArray(`in`)
    }

    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                out.writeInt(id)
                writeByteArray(out, sigma)
                writeByteArray(out, signingPublicKey)
                writeByteArray(out, randomPublicKey)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    override fun toString(): String {
        return """
            SchnorrSignature {
                sigma: ${BigInteger(sigma).toString(16).uppercase(Locale.getDefault())},
                signingPk: ${BigInteger(signingPublicKey).toString(16).uppercase(Locale.getDefault())},
                randomPk: ${BigInteger(randomPublicKey).toString(16).uppercase(Locale.getDefault())},
            }
        """.trimIndent()
    }

    companion object {
        fun buildFinalSignature(
            signatureResponse: UncombinedConfidentialResponse,
            schnorrSignatureScheme: SchnorrSignatureScheme,
            dataToSign: ByteArray,
            serviceProxy: ConfidentialServiceProxy,
        ): SchnorrSignature {
            lateinit var partialSignature: SchnorrPublicPartialSignature
            try {
                ByteArrayInputStream(signatureResponse.getPlainData()).use { bis ->
                    ObjectInputStream(bis).use { `in` ->
                        partialSignature = SchnorrPublicPartialSignature.deserialize(schnorrSignatureScheme, `in`)
                    }
                }
            } catch (e: Exception) { // IOException & ClassNotFoundException
                e.printStackTrace()
                serviceProxy.close()
                exitProcess(-1)
            }
            val signingPublicKey = schnorrSignatureScheme.decodePublicKey(partialSignature.getSigningPublicKey())

            val f = serviceProxy.currentF
            val signingKeyCommitment: EllipticCurveCommitment = partialSignature.getSigningKeyCommitment()
            val randomKeyCommitment: EllipticCurveCommitment = partialSignature.getRandomKeyCommitment()
            val randomPublicKey: ECPoint = partialSignature.getRandomPublicKey()
            val verifiableShares = signatureResponse.getVerifiableShares()[0]
            val partialSignatures = verifiableShares.map { it.share }.toTypedArray()

            val signature: SchnorrSignature = schnorrSignatureScheme.combinePartialSignatures(
                f,
                dataToSign,
                signingKeyCommitment,
                randomKeyCommitment,
                signingPublicKey,
                randomPublicKey,
                *partialSignatures
            )
            return signature
        }

        fun deserialize(serializedSignature: ByteArray): SchnorrSignature {
            ByteArrayInputStream(serializedSignature).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val keyScheme = KeyScheme.getScheme(`in`.readInt())
                    val sigma = readByteArray(`in`)
                    val signingPublicKey = readByteArray(`in`)
                    val randomPublicKey = readByteArray(`in`)
                    return SchnorrSignature(sigma, signingPublicKey, randomPublicKey)
                }
            }
        }
    }
}