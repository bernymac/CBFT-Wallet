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

package wallet.server

import bftsmart.communication.ServerCommunicationSystem
import bftsmart.tom.MessageContext
import bftsmart.tom.ServiceReplica
import wallet.signatures.bls.BlsSignatureScheme
import confidential.ConfidentialMessage
import confidential.EllipticCurveConstants
import confidential.facade.server.ConfidentialSingleExecutable
import confidential.polynomial.DistributedPolynomialManager
import confidential.polynomial.RandomKeyPolynomialListener
import confidential.polynomial.RandomPolynomialContext
import confidential.polynomial.RandomPolynomialListener
import confidential.server.ConfidentialRecoverable
import confidential.server.ServerConfidentialityScheme
import confidential.statemanagement.ConfidentialSnapshot
import wallet.communications.*
import wallet.communications.Operation.*
import wallet.dprf.DPRFParameters
import wallet.dprf.DPRFResult
import wallet.encryption.CiphertextMetadata
import wallet.encryption.CommittedData
import wallet.encryption.DiSE
import wallet.exceptions.InvalidKeySchemeException
import wallet.exceptions.KeyPairNotFoundException
import wallet.exceptions.OperationNotFoundException
import wallet.signatures.schnorr.SchnorrPublicPartialSignature
import wallet.signatures.schnorr.SchnorrSignatureScheme
import wallet.signatures.KeyScheme
import wallet.signatures.bls.BlsSignature
import org.bouncycastle.math.ec.ECPoint
import org.slf4j.LoggerFactory
import vss.commitment.ellipticCurve.EllipticCurveCommitment
import vss.commitment.linear.LinearCommitments
import vss.secretsharing.Share
import vss.secretsharing.VerifiableShare
import java.io.*
import java.math.BigInteger
import java.security.MessageDigest
import java.util.*
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import kotlin.collections.HashMap
import kotlin.concurrent.withLock
import kotlin.system.exitProcess

private typealias PolynomialId = Int
private typealias ClientId = Int
private typealias IndexId = String
private data class RequestOperation(val clientId: Int, val operation: Operation)
private data class KeyGenerationData(val keyGenerationRequest: KeyGenerationRequest, val messageContext: MessageContext)
private data class SignatureRequestDto(val privateKeyId: String, val dataToSign: ByteArray, val keyScheme: KeyScheme, val messageContext: MessageContext)

class Server(private val id: Int): ConfidentialSingleExecutable, RandomPolynomialListener, RandomKeyPolynomialListener {
    private val logger = LoggerFactory.getLogger("wallet")
    private val serverCommunicationSystem: ServerCommunicationSystem
    private val distributedPolynomialManager: DistributedPolynomialManager
    private val serviceReplica: ServiceReplica
    private val cr: ConfidentialRecoverable
    private val messageDigest: MessageDigest

    // Used during requests and data map accesses
    private val lock: Lock

    // Stores requests to get random number
    private var requests: MutableMap<PolynomialId, MessageContext>

    // Stores clients' random number shares of clients
    private var data: MutableMap<ClientId, VerifiableShare>         // <client id, random number's share>

    // Stores data for signing
    private val signingData: Map<ClientId, ByteArray>               // <client id, data for signing>

    // Stores the private key shares of each client
    data class SignatureKeyPair(val privateKeyShare: VerifiableShare, val publicKey: ByteArray, val keyScheme: KeyScheme)

    private val indexKeys: HashMap<ClientId, HashSet<IndexId>>
    private val db: HashMap<IndexId, SignatureKeyPair>                // <client id + key id, signature key pair>

    // Stores requests for generating a random key and associates the polynomial id with the corresponding operation
    private val randomKeyGenerationRequests: MutableMap<PolynomialId, RequestOperation>

    // Stores requests for generating a signing key
    private val signKeyGenerationRequests: MutableMap<ClientId, KeyGenerationData>
    private val signKeyGenRequests: MutableMap<IndexId, KeyGenerationData>
    private val signKeyGenPolyIds: MutableMap<PolynomialId, IndexId>

    // Stores requests for issuing a signature
    private val signatureRequests: MutableMap<ClientId, SignatureRequestDto>

    private val schnorrSignatureScheme: SchnorrSignatureScheme
    private val blsSignatureScheme: BlsSignatureScheme

    private val dise: DiSE
    private val dprfParameters: MutableMap<IndexId, DPRFParameters>

    init {
        lock = ReentrantLock(true)
        messageDigest = MessageDigest.getInstance("SHA256")
        requests = TreeMap()
        data = TreeMap()
        signingData = TreeMap()
        cr = ConfidentialRecoverable(id, this)
        serviceReplica = ServiceReplica(id, cr, cr, cr)
        serverCommunicationSystem = serviceReplica.serverCommunicationSystem
        distributedPolynomialManager = cr.distributedPolynomialManager
        distributedPolynomialManager.setRandomPolynomialListener(this)
        distributedPolynomialManager.setRandomKeyPolynomialListener(this)

        indexKeys = HashMap()
        db = HashMap()

        randomKeyGenerationRequests = TreeMap()
        signKeyGenerationRequests = TreeMap()
        signKeyGenRequests = TreeMap()
        signKeyGenPolyIds = TreeMap()
        signatureRequests = TreeMap()

        val confidentialitySchemes = HashMap<String, ServerConfidentialityScheme>()
        confidentialitySchemes[EllipticCurveConstants.BLS12_381.NAME] =
            ServerConfidentialityScheme(
                id,
                serviceReplica.replicaContext.currentView,
                EllipticCurveConstants.BLS12_381.PARAMETERS
            )
        confidentialitySchemes[EllipticCurveConstants.secp256r1.NAME] =
            ServerConfidentialityScheme(
                id,
                serviceReplica.replicaContext.currentView,
                EllipticCurveConstants.secp256r1.PARAMETERS
            )
        confidentialitySchemes[EllipticCurveConstants.secp256k1.NAME] =
            ServerConfidentialityScheme(
                id,
                serviceReplica.replicaContext.currentView,
                EllipticCurveConstants.secp256k1.PARAMETERS
            )
        cr.registerConfidentialitySchemes(confidentialitySchemes)

        schnorrSignatureScheme = SchnorrSignatureScheme()
        blsSignatureScheme = BlsSignatureScheme(serviceReplica.replicaContext.currentView.f)

        dise = DiSE(cr.shareholderId, serviceReplica.replicaContext.currentView.f, EllipticCurveConstants.secp256r1.PARAMETERS)
        dprfParameters = HashMap()
    }

    override fun appExecuteOrdered(
        bytes: ByteArray,
        verifiableShares: Array<VerifiableShare?>?,
        messageContext: MessageContext
    ): ConfidentialMessage? {
        val messageSenderId = messageContext.sender
        val op = Operation.getOperation(bytes[0].toInt())
        val receivedData = bytes.copyOfRange(1, bytes.size)
        logger.info("Received a {} request from {} in cid {}", op, messageSenderId, messageContext.consensusId)
        when (op) {
            GENERATE_SIGNING_KEY -> {
                lock.withLock {
                    val keyGenRequest = KeyGenerationRequest.deserialize(receivedData)
                    val indexKey = buildDatabaseIndexKey(keyGenRequest.privateKeyId, messageSenderId)

                    if (db.containsKey(indexKey)) {
                        logger.warn("Already exists a signing key associated with index key.")
                        sendSuccessfulMessageTo(messageContext)
                    } else if (!signKeyGenRequests.containsKey(indexKey)) {
                        signKeyGenRequests[indexKey] = KeyGenerationData(keyGenRequest, messageContext)
                        val polynomialId = generateSigningKey(
                            when (keyGenRequest.keyScheme) {
                                KeyScheme.SCHNORR -> EllipticCurveConstants.secp256k1.NAME
                                KeyScheme.BLS -> EllipticCurveConstants.BLS12_381.NAME
                                KeyScheme.SYMMETRIC -> EllipticCurveConstants.secp256r1.NAME
                            }
                        )
                        randomKeyGenerationRequests[polynomialId] = RequestOperation(messageSenderId, GENERATE_SIGNING_KEY)

                        signKeyGenPolyIds[polynomialId] = indexKey
                        logger.info("Generating signing key with polynomial id {}", polynomialId)
                    } else {
                        logger.warn("Signing key is already being created.")
                    }
                }
            }
            SIGN_DATA -> {
                lock.withLock {
                    val signatureRequestDto = SignatureRequest.deserialize(receivedData).toDto(messageContext)
                    signatureRequests[messageSenderId] = signatureRequestDto

                    when (signatureRequestDto.keyScheme) {
                        KeyScheme.SCHNORR -> {
                            // In case of Schnorr signature we need to generate a new random key-pair
                            val polynomialId = generateSigningKey(EllipticCurveConstants.secp256k1.NAME)
                            randomKeyGenerationRequests[polynomialId] = RequestOperation(messageSenderId, SIGN_DATA)
                        }
                        KeyScheme.BLS -> {
                            signBlsAndSend(messageSenderId)
                        }
                        else -> throw InvalidKeySchemeException("Invalid signature scheme")
                    }
                }
            }
            GET_PUBLIC_KEY -> {
                val pkRequest = PublicKeyRequest.deserialize(receivedData)
                val indexKey = buildDatabaseIndexKey(pkRequest.indexId, messageSenderId)

                sendPublicKeyTo(db[indexKey]!!.keyScheme, db[indexKey]!!.publicKey, messageContext)
            }
            ENCRYPT -> {
                val encryptorId = messageSenderId
                val encDecRequest = EncDecRequest.deserialize(receivedData)
                val committedData = CommittedData.deserialize(encDecRequest.data)
                val evalInput = BigInteger(1, "$encryptorId".toByteArray().plus(committedData.alpha))
                performAndSendContribution(evalInput, dprfParameters[encDecRequest.indexId]!!, messageContext)
            }
            DECRYPT -> {
                val encDecRequest = EncDecRequest.deserialize(receivedData)
                val ciphertextMeta = CiphertextMetadata.deserialize(encDecRequest.data)
                val evalInput = BigInteger(1, "${ciphertextMeta.encryptorId}".toByteArray().plus(ciphertextMeta.alpha))
                performAndSendContribution(evalInput, dprfParameters[encDecRequest.indexId]!!, messageContext)
            }
            AVAILABLE_KEYS -> {
                sendClientAvailableKeyIds(messageContext)
            }
            else -> return null
        }
        return null
    }

    /**
     * Generates a signing key through the COBRA's distributed polynomial protocol.
     * @param confidentialitySchemeId identifier of the confidentiality scheme to select the correct elliptic curve.
     * @return the identifier of the distributed polynomial that will be created.
     */
    private fun generateSigningKey(confidentialitySchemeId: String): Int {
        return distributedPolynomialManager.createRandomKeyPolynomial(
            serviceReplica.replicaContext.currentView.f,
            serviceReplica.replicaContext.currentView.processes,
            confidentialitySchemeId
        )
    }

    /**
     * Method called by the polynomial generation manager when the requested random key is generated
     * @param context Random number share and its context
     */
    override fun onRandomKeyPolynomialsCreation(context: RandomPolynomialContext) {
        lock.lock()
        val privateKeyShare = context.point
        val commitment = (context.point.commitments as EllipticCurveCommitment).commitment
        val publicKey = commitment[commitment.size - 1]
        onRandomKey(context.initialId, privateKeyShare, publicKey)
        lock.unlock()
    }

    /**
     * Stores the generated private key share in the database and sends the corresponding public key to the respective
     * client.
     */
    private fun onRandomKey(polynomialId: Int, privateKeyShare: VerifiableShare, publicKey: ECPoint) {
        val indexId = signKeyGenPolyIds.remove(polynomialId)
        if (indexId == null && !randomKeyGenerationRequests.containsKey(polynomialId)) {
            logger.warn("Received an unknown polynomial id {}", polynomialId)
            return
        }
        logger.info("Received key share of the random signing key generated from the polynomial id {}", polynomialId)

        val (clientId, operation) = randomKeyGenerationRequests.remove(polynomialId)!!
        when (operation) {
            GENERATE_SIGNING_KEY -> {
                val (keyGenRequest, messageContext) = signKeyGenRequests.remove(indexId)!!
                val databaseIndexKey = buildDatabaseIndexKey(keyGenRequest.privateKeyId, messageContext.sender)

                val publicKeyEncoded = when (keyGenRequest.keyScheme) {
                    KeyScheme.SCHNORR -> publicKey.getEncoded(true)
                    KeyScheme.BLS -> blsSignatureScheme.computePublicKey(privateKeyShare.share.share)
                    KeyScheme.SYMMETRIC -> {
                        dprfParameters[keyGenRequest.privateKeyId] = dise.init(
                            privateKeyShare.share,
                            BigInteger(getPublicKey(privateKeyShare).getEncoded(true))
                        )
                        ByteArray(0)
                    }
                }
                val signatureKeyPair = SignatureKeyPair(privateKeyShare, publicKeyEncoded, keyGenRequest.keyScheme)

                val clientIndexesSet = indexKeys[clientId]?.apply { add(databaseIndexKey) } ?: HashSet<IndexId>().apply { add(databaseIndexKey) }
                indexKeys[clientId] = clientIndexesSet

                db[databaseIndexKey] = signatureKeyPair
                sendSuccessfulMessageTo(messageContext)
            }
            SIGN_DATA -> {
                val (privateKeyId, dataToSign, signatureScheme, messageContext) = signatureRequests.remove(clientId)!!
                require(signatureScheme == KeyScheme.SCHNORR) { "Only Schnorr needs to generate a new random value." }
                val chosenSignatureKeypair = getSignatureKeyPair(privateKeyId, messageContext.sender) ?: throw KeyPairNotFoundException("Schnorr key pair not found.")

                logger.info("Computing partial Schnorr signature for client {}", clientId)
                val randomPrivateKeyShare = privateKeyShare
                val randomPublicKey = publicKey
                signSchnorrAndSend(messageContext, dataToSign, chosenSignatureKeypair, randomPrivateKeyShare, randomPublicKey)
            }
            else -> throw OperationNotFoundException("Random key generation does not match with any available operation.")
        }
    }

    /**
     * Issues a BLS signature for the provided data, more specifically a partial signature, and then sends it to the
     * corresponding client.
     */
    private fun signBlsAndSend(clientId: Int) {
        val (privateKeyId, dataToSign, _, receiverContext) = signatureRequests.remove(clientId)!!
        val chosenSigningKeyPair = getSignatureKeyPair(privateKeyId, receiverContext.sender) ?: throw KeyPairNotFoundException("BLS key pair not found.")
        logger.info("Computing partial BLS signature for client {}", clientId)

        val privateKeyShare = chosenSigningKeyPair.privateKeyShare.share.share

        val partialSignatureBytes = blsSignatureScheme.sign(privateKeyShare.toByteArray(), dataToSign)

        val partialSignature = BlsSignature(partialSignatureBytes, chosenSigningKeyPair.publicKey)

        val partialSignatureWithPubKey = VerifiableShare(
            Share(cr.shareholderId, BigInteger(partialSignature.serialize())),
            LinearCommitments(BigInteger.ZERO),
            null
        )

        val response = ConfidentialMessage(ByteArray(0), partialSignatureWithPubKey)
        sendResponseTo(receiverContext, response)
        logger.info("Sent partial BLS signature for client {}", receiverContext.sender)
    }

    /**
     * Sends the contribution back to the client that is responsible for the encryption/decryption.
     */
    private fun performAndSendContribution(evalInput: BigInteger, dprfParameters: DPRFParameters, receiverContext: MessageContext) {
        val contribution = dise.performContribution(evalInput, dprfParameters)
        val contributionBytes = VerifiableShare(
            Share(cr.shareholderId, BigInteger(DPRFResult(contribution, dprfParameters.publicParameters).serialize())),
            LinearCommitments(BigInteger.ZERO),
            null
        )

        val response = ConfidentialMessage(ByteArray(0), contributionBytes)
        sendResponseTo(receiverContext, response)
        logger.info("Sent encryption/decryption contribution for client {}", receiverContext.sender)
    }

    private fun sendClientAvailableKeyIds(receiverContext: MessageContext) {
        val clientId = receiverContext.sender
        var serializedData = ByteArray(0)

        val indexIds = indexKeys[clientId]
        if (indexIds != null) {
            ByteArrayOutputStream().use { bos ->
                ObjectOutputStream(bos).use { out ->
                    out.writeInt(indexIds.size)
                    for (indexKey in indexIds) {
                        val keyData = db[indexKey]!!
                        val indexId = indexKey.drop(clientId.toString().length)
                        out.writeUTF(indexId)
                        writeByteArray(out, keyData.publicKey)
                        out.writeInt(keyData.keyScheme.ordinal)
                    }
                    out.flush()
                    bos.flush()
                    serializedData = bos.toByteArray()
                }
            }
        }

        val availableKeys = VerifiableShare(
            Share(cr.shareholderId, BigInteger(serializedData)),
            LinearCommitments(BigInteger.ZERO),
            null
        )

        val response = ConfidentialMessage(ByteArray(0), availableKeys)
        sendResponseTo(receiverContext, response)
        logger.info("Sent available key ids for client {}", receiverContext.sender)
    }

    /**
     * Builds the index key associated to a private key share. The index key is composed by the sender id / client id
     * concatenated with the identifier sent by the client to be associated with the generated private key share.
     * @return the index key associated with a private key share.
     */
    private fun buildDatabaseIndexKey(keyIdentifier: String, messageSenderId: Int): String {
        return "$messageSenderId$keyIdentifier"
    }

    /**
     * Obtains the public key associated with the provided private key share.
     * @param privateKeyShare private key share of the desired public key.
     * @return the corresponding public key.
     */
    private fun getPublicKey(privateKeyShare: VerifiableShare): ECPoint {
        val commitment = (privateKeyShare.commitments as EllipticCurveCommitment).commitment
        return commitment[commitment.size - 1]
    }

    /**
     * Sends a public key as the response message to a specific client.
     * @param keyScheme Key scheme associated to the public key.
     * @param publicKey Public key to send to the client.
     * @param receiverContext Information about the requesting client.
     */
    private fun sendPublicKeyTo(keyScheme: KeyScheme, publicKey: ByteArray, receiverContext: MessageContext) {
        val response = when (keyScheme) {
            KeyScheme.SCHNORR -> ConfidentialMessage(publicKey)
            KeyScheme.BLS -> ConfidentialMessage(
                ByteArray(0),
                VerifiableShare(
                    Share(cr.shareholderId, BigInteger(publicKey)),
                    LinearCommitments(BigInteger.ZERO),
                    null
                )
            )
            else -> throw InvalidKeySchemeException("Invalid signature scheme")
        }
        sendResponseTo(receiverContext, response)
    }

    /**
     * Sends a successful message to a specific client.
     */
    private fun sendSuccessfulMessageTo(receiverContext: MessageContext) {
        val response = ConfidentialMessage(
            ByteArray(0),
            VerifiableShare(
                Share(cr.shareholderId, BigInteger("1")),
                LinearCommitments(BigInteger.ZERO),
                null
            )
        )
        sendResponseTo(receiverContext, response)
    }

    /**
     * Sends a response to a specific client.
     * @param receiverContext Information about the requesting client.
     * @param response The response to send back to the client.
     */
    private fun sendResponseTo(receiverContext: MessageContext, response: ConfidentialMessage) {
        cr.sendMessageToClient(receiverContext, response)
    }

    /**
     * Method called by the polynomial generation manager when the requested random number is generated
     * @param context Random number share and its context
     */
    override fun onRandomPolynomialsCreation(context: RandomPolynomialContext) {
        lock.lock()
        val delta = context.time / 1000000.0
        logger.debug("Received random number polynomial with id {} in {} ms", context.initialId, delta)
        val messageContext: MessageContext = requests.remove(context.initialId)!!
        data[messageContext.sender] = context.point
        logger.debug("Sending random number share to {}", messageContext.sender)
        sendRandomNumberShareTo(messageContext, context.point)
        lock.unlock()
    }

    /**
     * Method used to asynchronously send the random number share
     * @param receiverContext Information about the requesting client
     * @param share Random number share
     */
    private fun sendRandomNumberShareTo(receiverContext: MessageContext, share: VerifiableShare?) {
        val response = ConfidentialMessage(null, share)
        sendResponseTo(receiverContext, response)
    }

    private fun signSchnorrAndSend(
        receiverContext: MessageContext,
        data: ByteArray,
        chosenSigningKeyPair: SignatureKeyPair,
        randomPrivateKeyShare: VerifiableShare,
        randomPublicKey: ECPoint
    ) {
        val signingPrivateKeyShare: VerifiableShare = chosenSigningKeyPair.privateKeyShare
        val sigma = schnorrSignatureScheme.computePartialSignature(
            data,
            signingPrivateKeyShare.share.share,
            randomPrivateKeyShare.share.share,
            randomPublicKey
        ).add(if (serviceReplica.id == 0) BigInteger.ONE else BigInteger.ZERO)

        val publicPartialSignature = SchnorrPublicPartialSignature(
            signingPrivateKeyShare.commitments as EllipticCurveCommitment,
            randomPrivateKeyShare.commitments as EllipticCurveCommitment,
            randomPublicKey,
            chosenSigningKeyPair.publicKey
        )

        lateinit var plainData: ByteArray
        try {
            ByteArrayOutputStream().use { bos ->
                ObjectOutputStream(bos).use { out ->
                    publicPartialSignature.serialize(out)
                    out.flush()
                    bos.flush()
                    plainData = bos.toByteArray()
                }
            }
        } catch (e: IOException) {
            e.printStackTrace()
        }

        val partialSignature = VerifiableShare(
            Share(cr.shareholderId, sigma),
            LinearCommitments(BigInteger.ZERO),
            null
        )

        val response = ConfidentialMessage(plainData, partialSignature)
        sendResponseTo(receiverContext, response)
        logger.info("Sent partial Schnorr signature for client {}", receiverContext.sender)
    }

    /**
     * Obtains the private key share from the database if exists.
     * @return the private key share or null when it does not exist.
     */
    private fun getSignatureKeyPair(
        privateKeyId: String,
        messageSenderId: Int
    ) = db.get(buildDatabaseIndexKey(privateKeyId, messageSenderId))


    override fun appExecuteUnordered(
        bytes: ByteArray?,
        verifiableShares: Array<VerifiableShare?>?,
        messageContext: MessageContext?
    ): ConfidentialMessage? {
        return null
    }

    override fun getConfidentialSnapshot(): ConfidentialSnapshot? {
        try {
            ByteArrayOutputStream().use { bout ->
                ObjectOutputStream(bout).use { out ->
                    out.writeInt(requests.size)
                    for ((key, value) in requests) {
                        out.writeInt(key)
                        out.writeObject(value)
                    }
                    out.writeInt(data.size)
                    val shares = arrayOfNulls<VerifiableShare>(data.size)
                    for ((index, entry: Map.Entry<Int, VerifiableShare>) in data.entries.withIndex()) {
                        out.writeInt((entry.key))
                        entry.value.writeExternal(out)
                        shares[index] = entry.value
                    }
                    out.flush()
                    bout.flush()
                    return ConfidentialSnapshot(bout.toByteArray(), *shares)
                }
            }
        } catch (e: IOException) {
            logger.error("Error while taking snapshot", e)
        }
        return null
    }

    override fun installConfidentialSnapshot(confidentialSnapshot: ConfidentialSnapshot) {
        try  {
            ByteArrayInputStream(confidentialSnapshot.plainData).use { bin ->
                ObjectInputStream(bin).use { `in` ->
                    var size = `in`.readInt()
                    requests = TreeMap<Int, MessageContext>()
                    while (size-- > 0) {
                        val key: Int = `in`.readInt()
                        val value: MessageContext = `in`.readObject() as MessageContext
                        requests[key] = value
                    }
                    size = `in`.readInt()
                    data = TreeMap<Int, VerifiableShare>()
                    val shares: Array<VerifiableShare> = confidentialSnapshot.shares
                    for (i in 0..<size) {
                        val key: Int = `in`.readInt()
                        val value: VerifiableShare = shares[i]
                        value.readExternal(`in`)
                        data[key] = value
                    }
                }
            }
        } catch (e: Exception) {
            when (e) {
                is IOException,
                is ClassCastException,
                is ClassNotFoundException -> logger.error("Error while installing snapshot", e)
            }
        }
    }
}

private fun SignatureRequest.toDto(messageContext: MessageContext): SignatureRequestDto = SignatureRequestDto(
    privateKeyId, dataToSign, keyScheme, messageContext
)



fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: wallet.server.ServerKt <server id>")
        exitProcess(-1)
    }
    Server(args[0].toInt())
}