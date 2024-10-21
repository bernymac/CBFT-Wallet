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

/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class wallet_signatures_bls_BlsSignatureScheme */

#ifndef _Included_wallet_signatures_bls_BlsSignatureScheme
#define _Included_wallet_signatures_bls_BlsSignatureScheme
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     wallet_signatures_bls_BlsSignatureScheme
 * Method:    initialize
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_wallet_signatures_bls_BlsSignatureScheme_initialize
  (JNIEnv *, jobject, jint);

/*
 * Class:     wallet_signatures_bls_BlsSignatureScheme
 * Method:    getOrderBytes
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_wallet_signatures_bls_BlsSignatureScheme_getOrderBytes
  (JNIEnv *, jobject);

/*
 * Class:     wallet_signatures_bls_BlsSignatureScheme
 * Method:    computeKeyPair
 * Signature: ()[[B
 */
JNIEXPORT jobjectArray JNICALL Java_wallet_signatures_bls_BlsSignatureScheme_computeKeyPair
  (JNIEnv *, jobject);

/*
 * Class:     wallet_signatures_bls_BlsSignatureScheme
 * Method:    computePublicKey
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_wallet_signatures_bls_BlsSignatureScheme_computePublicKey
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     wallet_signatures_bls_BlsSignatureScheme
 * Method:    computeSignature
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_wallet_signatures_bls_BlsSignatureScheme_computeSignature
  (JNIEnv *, jobject, jbyteArray, jbyteArray);

/*
 * Class:     wallet_signatures_bls_BlsSignatureScheme
 * Method:    computeVerification
 * Signature: ([B[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_wallet_signatures_bls_BlsSignatureScheme_computeVerification
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     wallet_signatures_bls_BlsSignatureScheme
 * Method:    interpolatePartialSignatures
 * Signature: ([[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_wallet_signatures_bls_BlsSignatureScheme_interpolatePartialSignatures
  (JNIEnv *, jobject, jobjectArray);

/*
 * Class:     wallet_signatures_bls_BlsSignatureScheme
 * Method:    interpolatePartialPublicKeys
 * Signature: ([[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_wallet_signatures_bls_BlsSignatureScheme_interpolatePartialPublicKeys
  (JNIEnv *, jobject, jobjectArray);

#ifdef __cplusplus
}
#endif
#endif