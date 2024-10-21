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

import wallet.client.UncombinedConfidentialResponse
import wallet.communications.readByteArray
import wallet.communications.writeByteArray
import wallet.signatures.KeyScheme
import java.io.*
import java.math.BigInteger
import java.util.*

class BlsSignature(
    private var signature: ByteArray,
    private var signingPublicKey: ByteArray,
) : Externalizable {

    // Identifier used to identify the corresponding signature scheme when deserializing a signature
    private val id = KeyScheme.BLS.ordinal

    fun getSignature() = signature
    fun getSigningPublicKey() = signingPublicKey

    override fun writeExternal(out: ObjectOutput) {
        writeByteArray(out, signature)
        writeByteArray(out, signingPublicKey)
    }

    override fun readExternal(`in`: ObjectInput) {
        signature = readByteArray(`in`)
        signingPublicKey = readByteArray(`in`)
    }

    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                out.writeInt(id)
                writeByteArray(out, signature)
                writeByteArray(out, signingPublicKey)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    override fun toString(): String {
        return """
            BlsSignature {
                signature: ${BigInteger(signature).toString(16).uppercase(Locale.getDefault())},
                pk: ${BigInteger(signingPublicKey).toString(16).uppercase(Locale.getDefault())}
            }
        """.trimIndent()
    }

    companion object {
        fun buildFinalSignature(
            signatureResponse: UncombinedConfidentialResponse,
            blsSignatureScheme: BlsSignatureScheme,
            dataToSign: ByteArray,
        ): BlsSignature {
            val verifiableShares = signatureResponse.getVerifiableShares()[0]
            val partialSignaturesWithPubKeys = verifiableShares.associate {
                it.share.shareholder to deserialize(it.share.share.toByteArray())
            }

            val partialSignatures = partialSignaturesWithPubKeys.keys.associateWith { shareholder ->
                partialSignaturesWithPubKeys[shareholder]!!.signature
            }
            val partialPubKeys = partialSignaturesWithPubKeys.keys.associateWith { shareholder ->
                partialSignaturesWithPubKeys[shareholder]!!.signingPublicKey
            }

            val signature = blsSignatureScheme.combinePartialSignatures(partialSignatures, partialPubKeys, dataToSign)
            val publicKey = blsSignatureScheme.combinePartialPublicKeys(partialPubKeys)
            val blsSignature = BlsSignature(signature, publicKey)
            return blsSignature
        }

        fun buildFinalPublicKey(signatureResponse: UncombinedConfidentialResponse, blsSignatureScheme: BlsSignatureScheme): ByteArray {
            val verifiableShares = signatureResponse.getVerifiableShares()[0]
            val partialSignaturesWithPubKeys = verifiableShares.associate {
                it.share.shareholder to it.share.share.toByteArray()
            }

            val publicKey = blsSignatureScheme.combinePartialPublicKeys(partialSignaturesWithPubKeys)
            return publicKey
        }

        fun deserialize(data: ByteArray): BlsSignature {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val keyScheme = KeyScheme.getScheme(`in`.readInt())
                    val signature = readByteArray(`in`)
                    val signingPublicKey = readByteArray(`in`)
                    return BlsSignature(signature, signingPublicKey)
                }
            }
        }
    }
}