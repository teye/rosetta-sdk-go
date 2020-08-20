// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keys

import (
	"fmt"
	"testing"

	"github.com/coinbase/rosetta-sdk-go/types"

	zilUtil "github.com/Zilliqa/gozilliqa-sdk/util"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func hash(message string) []byte {
	messageHashBytes := common.BytesToHash([]byte(message)).Bytes()
	return messageHashBytes
}

var signerSecp256k1 Signer

func init() {
	keypair, _ := GenerateKeypair(types.Secp256k1)
	signerSecp256k1, _ = keypair.Signer()
}

func TestSignSecp256k1(t *testing.T) {
	type payloadTest struct {
		payload *types.SigningPayload
		sigType types.SignatureType
		sigLen  int
		err     bool
		errMsg  string
	}

	var payloadTests = []payloadTest{
		{mockPayload(hash("hello123"), types.Ecdsa), types.Ecdsa, 64, false, ""},
		{mockPayload(hash("hello1234"), types.EcdsaRecovery), types.EcdsaRecovery, 65, false, ""},
		{mockPayload(hash("hello123"), types.Ed25519), types.Ed25519, 64, true, "unsupported signature type"},
	}

	for _, test := range payloadTests {
		signature, err := signerSecp256k1.Sign(test.payload, test.sigType)

		if !test.err {
			assert.NoError(t, err)
			assert.Equal(t, len(signature.Bytes), test.sigLen)
		} else {
			assert.Contains(t, err.Error(), test.errMsg)
		}
	}
}

func mockSecpSignature(
	sigType types.SignatureType,
	pubkey *types.PublicKey,
	msg, sig []byte,
) *types.Signature {
	payload := &types.SigningPayload{
		Address:       "test",
		Bytes:         msg,
		SignatureType: sigType,
	}

	mockSig := &types.Signature{
		SigningPayload: payload,
		PublicKey:      pubkey,
		SignatureType:  sigType,
		Bytes:          sig,
	}
	return mockSig
}

func TestVerifySecp256k1(t *testing.T) {
	type signatureTest struct {
		signature *types.Signature
		errMsg    string
	}

	payloadEcdsa := &types.SigningPayload{
		Address:       "test",
		Bytes:         hash("hello"),
		SignatureType: types.Ecdsa,
	}
	payloadEcdsaRecovery := &types.SigningPayload{
		Address:       "test",
		Bytes:         hash("hello"),
		SignatureType: types.EcdsaRecovery,
	}

	payloadSchnorr1 := &types.SigningPayload{
		Address:       "test",
		Bytes:         []byte("{\"amount\":2000000000000,\"code\":\"\",\"data\":\"\",\"gasLimit\":1,\"gasPrice\":1000000000,\"nonce\":186,\"toAddr\":\"zil1f9uqwhwkq7fnzgh5x4djyzg4a7j3apx8dsnnc0\",\"version\":21823489}"),
		SignatureType: types.Schnorr1,
	}
	testSignatureEcdsa, _ := signerSecp256k1.Sign(payloadEcdsa, types.Ecdsa)
	testSignatureEcdsaRecovery, _ := signerSecp256k1.Sign(payloadEcdsaRecovery, types.EcdsaRecovery)
	testSignatureSchnorr1, _ := signerSecp256k1.Sign(payloadSchnorr1, types.Schnorr1)

	fmt.Printf("signature schnorr1 :%v\n", testSignatureSchnorr1)

	var signatureTests = []signatureTest{
		{mockSecpSignature(
			types.Ed25519,
			signerSecp256k1.PublicKey(),
			hash("hello"),
			make([]byte, 33)), "ed25519 is not supported"},
		{mockSecpSignature(
			types.Ecdsa,
			signerSecp256k1.PublicKey(),
			hash("hello"),
			make([]byte, 33)), "verify returned false"},
	}

	for _, test := range signatureTests {
		err := signerSecp256k1.Verify(test.signature)
		assert.Contains(t, err.Error(), test.errMsg)
	}

	goodEcdsaSignature := mockSecpSignature(
		types.Ecdsa,
		signerSecp256k1.PublicKey(),
		hash("hello"),
		testSignatureEcdsa.Bytes)
	goodEcdsaRecoverySignature := mockSecpSignature(
		types.EcdsaRecovery,
		signerSecp256k1.PublicKey(),
		hash("hello"),
		testSignatureEcdsaRecovery.Bytes)
	goodSchnorr1Signature := mockSecpSignature(
		types.Schnorr1,
		signerSecp256k1.PublicKey(),
		[]byte("{\"amount\":2000000000000,\"code\":\"\",\"data\":\"\",\"gasLimit\":1,\"gasPrice\":1000000000,\"nonce\":186,\"toAddr\":\"zil1f9uqwhwkq7fnzgh5x4djyzg4a7j3apx8dsnnc0\",\"version\":21823489}"),
		testSignatureSchnorr1.Bytes)
	assert.Equal(t, nil, signerSecp256k1.Verify(goodSchnorr1Signature))
	assert.Equal(t, nil, signerSecp256k1.Verify(goodEcdsaSignature))
	assert.Equal(t, nil, signerSecp256k1.Verify(goodEcdsaRecoverySignature))
}

func TestDemo(t *testing.T) {
	var signer2 Signer
	keypair2 := &KeyPair{
		PublicKey: &types.PublicKey{
			Bytes:     zilUtil.DecodeHex("public_key"),
			CurveType: "secp256k1",
		},
		PrivateKey: zilUtil.DecodeHex("private_key"),
	}
	payloadSchnorr1 := &types.SigningPayload{
		Address:       "sender_address",
		Bytes:         []byte("{\"amount\":2000000000000,\"code\":\"\",\"data\":\"\",\"gasLimit\":1,\"gasPrice\":1000000000,\"nonce\":187,\"senderAddr\":\"zil1n8uafq4thhzlq5nj50p55al9jvamr3s45hm49r\",\"toAddr\":\"zil1f9uqwhwkq7fnzgh5x4djyzg4a7j3apx8dsnnc0\",\"version\":21823489}"),
		SignatureType: types.Schnorr1,
	}

	signer2, _ = keypair2.Signer()

	testSignature, _ := signer2.Sign(payloadSchnorr1, types.Schnorr1)

	goodSchnorr1Sig := mockSecpSignature(
		types.Schnorr1,
		signer2.PublicKey(),
		[]byte("{\"amount\":2000000000000,\"code\":\"\",\"data\":\"\",\"gasLimit\":1,\"gasPrice\":1000000000,\"nonce\":187,\"senderAddr\":\"zil1n8uafq4thhzlq5nj50p55al9jvamr3s45hm49r\",\"toAddr\":\"zil1f9uqwhwkq7fnzgh5x4djyzg4a7j3apx8dsnnc0\",\"version\":21823489}"),
		testSignature.Bytes)

	assert.Equal(t, nil, signer2.Verify(goodSchnorr1Sig))
}
