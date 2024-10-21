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
import java.io.ObjectInput
import java.io.ObjectOutput
import java.math.BigInteger


class DPRFPublicParameters(
    private val generator: BigInteger,
    private val generatorCommitment: BigInteger,
    private val secretKeyShareCommitments: Map<BigInteger, BigInteger>,
) {
    fun getGenerator(): BigInteger {
        return generator
    }

    fun getGeneratorCommitment(): BigInteger {
        return generatorCommitment
    }

    fun getSecretKeyShareCommitmentOf(shareholder: BigInteger): BigInteger {
        return secretKeyShareCommitments[shareholder] ?: throw Exception("Share doesn't exist for shareholder: $shareholder")
    }

    fun writeExternal(out: ObjectOutput) {
        serializeBigInteger(generator, out)
        serializeBigInteger(generatorCommitment, out)
        serializeBigInteger(secretKeyShareCommitments.keys.first(), out)
        serializeBigInteger(secretKeyShareCommitments.values.first(), out)
    }

    companion object {
        fun readExternal(`in`: ObjectInput): DPRFPublicParameters {
            val generator = deserializeBigInteger(`in`)
            val generatorCommitment = deserializeBigInteger(`in`)
            val secretKeyShareShareholder = deserializeBigInteger(`in`)
            val secretKeyShareCommitment = deserializeBigInteger(`in`)
            return DPRFPublicParameters(generator, generatorCommitment, mapOf(secretKeyShareShareholder to secretKeyShareCommitment))
        }
    }

    override fun toString(): String {
        return "DPRFPublicParameters{generator=${generator.toString(16)},\ngeneratorCommitment=${generatorCommitment.toString(16)},\nsecretKeyShareCommitments=$secretKeyShareCommitments}"
    }
}
