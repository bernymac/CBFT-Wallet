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

package wallet.communications

import wallet.signatures.KeyScheme
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

private val OPERATION = Operation.GET_PUBLIC_KEY

class PublicKeyRequest(val indexId: String, val keyScheme: KeyScheme) {
    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                out.writeUTF(indexId)
                writeByteArray(out, byteArrayOf(keyScheme.ordinal.toByte()))
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return OPERATION.ordinal.toByte().joinByteArray(serializedData)
    }

    companion object {
        fun deserialize(data: ByteArray): PublicKeyRequest {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    return PublicKeyRequest(`in`.readUTF(), KeyScheme.getScheme(readByteArray(`in`)[0].toInt()))
                }
            }
        }
    }
}