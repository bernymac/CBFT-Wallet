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

package wallet.encryption

import wallet.communications.deserializeBigInteger
import wallet.communications.readByteArray
import wallet.communications.serializeBigInteger
import wallet.communications.writeByteArray
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.math.BigInteger
import java.util.*

class DiSECiphertext(
    val encryptorId: BigInteger,
    val alpha: ByteArray,
    val encryptedData: ByteArray,
) {

    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                serializeBigInteger(encryptorId, out)
                writeByteArray(out, alpha)
                writeByteArray(out, encryptedData)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    companion object {
         fun deserialize(data: ByteArray): DiSECiphertext {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val encryptorId = deserializeBigInteger(`in`)
                    val alpha = readByteArray(`in`)
                    val encryptedData = readByteArray(`in`)
                    return DiSECiphertext(encryptorId, alpha, encryptedData)
                }
            }
        }
    }

    override fun toString(): String {
        return """
            Ciphertext {
                encryptorId: $encryptorId,
                alpha: ${BigInteger(alpha).toString(16).uppercase(Locale.getDefault())},
                encryptedData: ${BigInteger(encryptedData).toString(16).uppercase(Locale.getDefault())},
            }
        """.trimIndent()
    }
}

class CiphertextMetadata(val encryptorId: BigInteger, val alpha: ByteArray) {
    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                serializeBigInteger(encryptorId, out)
                writeByteArray(out, alpha)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    companion object {
        fun deserialize(data: ByteArray): CiphertextMetadata {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    val encryptorId = deserializeBigInteger(`in`)
                    val alpha = readByteArray(`in`)
                    return CiphertextMetadata(encryptorId, alpha)
                }
            }
        }
    }
}

fun DiSECiphertext.toCiphertextMetadata() = CiphertextMetadata(encryptorId, alpha)
