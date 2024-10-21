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

package wallet.signatures

import java.security.InvalidParameterException

enum class KeyScheme {
    SCHNORR,
    BLS,
    SYMMETRIC;

    companion object {
        fun getScheme(ordinal: Int): KeyScheme {
            return KeyScheme.entries[ordinal]
        }
    }
}

fun stringToSignatureScheme(signatureSchemeStr: String): KeyScheme {
    return when (signatureSchemeStr) {
        "schnorr" -> KeyScheme.SCHNORR
        "bls" -> KeyScheme.BLS
        "symmetric" -> KeyScheme.SYMMETRIC
        else ->  throw InvalidParameterException("Invalid key scheme")
    }
}
