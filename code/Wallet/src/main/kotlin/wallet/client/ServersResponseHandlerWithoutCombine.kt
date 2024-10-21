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

package wallet.client

import bftsmart.tom.core.messages.TOMMessage
import confidential.ConfidentialMessage
import confidential.ExtractedResponse
import confidential.client.ClientConfidentialityScheme
import confidential.client.ServersResponseHandler
import vss.secretsharing.Share
import vss.secretsharing.VerifiableShare
import java.math.BigInteger
import java.util.*

class ServersResponseHandlerWithoutCombine(private val clientId: Int) : ServersResponseHandler() {
    override fun setClientConfidentialityScheme(confidentialityScheme: ClientConfidentialityScheme) {
        super.setClientConfidentialityScheme(confidentialityScheme)
    }

    override fun extractResponse(replies: Array<TOMMessage?>, sameContent: Int, lastReceived: Int): ExtractedResponse? {
        val lastMsg = replies[lastReceived]
        var response: ConfidentialMessage?
        val msgs: MutableMap<Int, LinkedList<ConfidentialMessage>> = HashMap()
        for (msg in replies) {
            if (msg == null) continue
            response = responses[msg.content]
            if (response == null) {
                logger.warn("Something went wrong while getting deserialized response from {}", msg.sender)
                continue
            }
            val responseHash = responseHashes[response]!!

            val msgList = msgs.computeIfAbsent(responseHash) { _ -> LinkedList() }
            msgList.add(response)
        }

        for (msgList in msgs.values) {
            if (msgList.size != sameContent) continue

            val firstMsg = msgList.first()
            val plainData = firstMsg.plainData

            if (firstMsg.shares == null) {
                return UncombinedConfidentialResponse(lastMsg!!.viewID, plainData)
            }

            // This response has secret data
            val numSecrets = firstMsg.shares.size
            val verifiableShares = ArrayList<LinkedList<VerifiableShare>>(numSecrets)
            (0..<numSecrets).forEach { _ -> verifiableShares.add(LinkedList()) }
            msgList.forEach { confidentialMessage ->
                val sharesI = confidentialMessage.shares
                (0..<numSecrets).forEachIndexed { i, _ -> verifiableShares[i].add(sharesI[i]) }
            }

            val sharedData: List<ByteArray> = verifiableShares.map { secretI -> secretI.first().sharedData }
            val allVerifiableShares = verifiableShares.map { secretI -> secretI.map { verifiableShare -> verifiableShare } }

            return UncombinedConfidentialResponse(lastMsg!!.viewID, plainData, allVerifiableShares, sharedData)
        }
        logger.error("This should not happen. Did not found {} equivalent responses", sameContent)
        return null
    }

    override fun reconstructShare(shareholder: BigInteger, serializedShare: ByteArray): Share {
        if (confidentialityScheme.useTLSEncryption()) {
            return Share(shareholder, BigInteger(serializedShare))
        }
        return Share(shareholder, confidentialityScheme.decryptShareFor(clientId, serializedShare))
    }
}
