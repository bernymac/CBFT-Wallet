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

import java.io.ObjectInput
import java.io.ObjectOutput
import java.math.BigInteger

fun writeByteArray(out: ObjectOutput, bytes: ByteArray?) {
    out.writeInt(bytes?.size ?: -1)
    if (bytes != null) out.write(bytes)
}

fun readByteArray(`in`: ObjectInput): ByteArray {
    val len = `in`.readInt()
    if (len == -1) return ByteArray(0)

    val result = ByteArray(len)
    `in`.readFully(result)
    return result
}

fun serializeBigInteger(value: BigInteger, out: ObjectOutput) {
    val b = value.toByteArray()
    out.writeInt(b.size)
    out.write(b)
}

fun deserializeBigInteger(`in`: ObjectInput): BigInteger {
    val len = `in`.readInt()
    val b = ByteArray(len)
    `in`.readFully(b)
    return BigInteger(b)
}

fun ByteArray.joinByteArray(bytesToJoin: ByteArray): ByteArray {
    val finalByteArray = ByteArray(this.size + bytesToJoin.size)
    System.arraycopy(this, 0, finalByteArray, 0, this.size)
    System.arraycopy(bytesToJoin, 0, finalByteArray, this.size, bytesToJoin.size)
    return finalByteArray
}

fun Byte.joinByteArray(bytesToJoin: ByteArray): ByteArray {
    val finalByteArray = ByteArray(1 + bytesToJoin.size)
    finalByteArray[0] = this
    System.arraycopy(bytesToJoin, 0, finalByteArray, 1, bytesToJoin.size)
    return finalByteArray
}
