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

import wallet.communications.readByteArray
import wallet.communications.writeByteArray
import org.bouncycastle.math.ec.ECPoint
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import java.io.ObjectInput
import java.io.ObjectOutput

class SchnorrPublicPartialSignature(
    private val signingKeyCommitment: EllipticCurveCommitment,
    private val randomKeyCommitment: EllipticCurveCommitment,
    private val randomPublicKey: ECPoint,
    private val signingPublicKey: ByteArray,
) {
    fun getSigningKeyCommitment() = signingKeyCommitment

    fun getRandomKeyCommitment() = randomKeyCommitment

    fun getRandomPublicKey() = randomPublicKey
    fun getSigningPublicKey() = signingPublicKey

    fun serialize(out: ObjectOutput) {
        signingKeyCommitment.writeExternal(out)
        randomKeyCommitment.writeExternal(out)
        val encoded = randomPublicKey.getEncoded(true)
        writeByteArray(out, encoded)
        writeByteArray(out, signingPublicKey)
    }

    companion object {
        fun deserialize(schnorrSignatureScheme: SchnorrSignatureScheme, `in`: ObjectInput): SchnorrPublicPartialSignature {
            val signingKeyCommitment = EllipticCurveCommitment(schnorrSignatureScheme.getCurve())
            signingKeyCommitment.readExternal(`in`)

            val randomKeyCommitment = EllipticCurveCommitment(schnorrSignatureScheme.getCurve())
            randomKeyCommitment.readExternal(`in`)

            val encoded = ByteArray(`in`.readInt())
            `in`.readFully(encoded)
            val randomPublicKey: ECPoint = schnorrSignatureScheme.decodePublicKey(encoded)

            val signingPublicKeyDecoded = readByteArray(`in`)
            return SchnorrPublicPartialSignature(signingKeyCommitment, randomKeyCommitment, randomPublicKey, signingPublicKeyDecoded)
        }
    }
}