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
/* Header for class vss_commitment_constant_Pairing */

#ifndef _Included_vss_commitment_constant_Pairing
#define _Included_vss_commitment_constant_Pairing
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    initialize
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_vss_commitment_constant_Pairing_initialize
  (JNIEnv *, jobject, jint);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    getOrderBytes
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_getOrderBytes
  (JNIEnv *, jobject);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    commit
 * Signature: ([Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_commit
  (JNIEnv *, jobject, jobjectArray);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    createWitness
 * Signature: ([Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_createWitness
  (JNIEnv *, jobject, jobjectArray);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    computePartialVerification
 * Signature: ([B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_computePartialVerification
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    verify
 * Signature: ([B[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_vss_commitment_constant_Pairing_verify
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    verifyWithoutPreComputation
 * Signature: ([B[B[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_vss_commitment_constant_Pairing_verifyWithoutPreComputation
  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    endVerification
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_vss_commitment_constant_Pairing_endVerification
  (JNIEnv *, jobject);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    startVerification
 * Signature: ([B)V
 */
JNIEXPORT void JNICALL Java_vss_commitment_constant_Pairing_startVerification
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    multiplyValues
 * Signature: ([[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_multiplyValues
  (JNIEnv *, jobject, jobjectArray);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    divideValues
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_divideValues
  (JNIEnv *, jobject, jbyteArray, jbyteArray);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    interpolateAndEvaluateAt
 * Signature: ([B[[[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_vss_commitment_constant_Pairing_interpolateAndEvaluateAt
  (JNIEnv *, jobject, jbyteArray, jobjectArray);

/*
 * Class:     vss_commitment_constant_Pairing
 * Method:    close
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_vss_commitment_constant_Pairing_close
  (JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif
#endif