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

package wallet.dprf

import wallet.communications.deserializeBigInteger
import wallet.communications.serializeBigInteger
import java.io.*
import java.math.BigInteger


class DPRFContribution(
    val h: BigInteger,
    val c: BigInteger,
    val u: BigInteger
) {

    override fun toString(): String {
        return """
            DPRFContribution {
                h=${h.toString(16)},
                c=${c.toString(16)},
                u=${u.toString(16)}
            }
            """.trimIndent()
    }

    fun serialize(): ByteArray {
        val serializedData: ByteArray
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { out ->
                serializeBigInteger(h, out)
                serializeBigInteger(c, out)
                serializeBigInteger(u, out)
                out.flush()
                bos.flush()
                serializedData = bos.toByteArray()
            }
        }
        return serializedData
    }

    fun writeExternal(out: ObjectOutput) {
        serializeBigInteger(h, out)
        serializeBigInteger(c, out)
        serializeBigInteger(u, out)
    }

    companion object {
        fun readExternal(`in`: ObjectInput): DPRFContribution {
            val h = deserializeBigInteger(`in`)
            val c = deserializeBigInteger(`in`)
            val u = deserializeBigInteger(`in`)
            return DPRFContribution(h, c, u)
        }
        fun deserialize(data: ByteArray): DPRFContribution {
            ByteArrayInputStream(data).use { bis ->
                ObjectInputStream(bis).use { `in` ->
                    return readExternal(`in`)
                }
            }
        }
    }
}
