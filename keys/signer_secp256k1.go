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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/coinbase/rosetta-sdk-go/asserter"
	"github.com/coinbase/rosetta-sdk-go/types"

	zilBech32 "github.com/Zilliqa/gozilliqa-sdk/bech32"
	zilSchnorr "github.com/Zilliqa/gozilliqa-sdk/schnorr"
	"github.com/Zilliqa/gozilliqa-sdk/transaction"
	zilUtil "github.com/Zilliqa/gozilliqa-sdk/util"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// SignerSecp256k1 is initialized from a keypair
type SignerSecp256k1 struct {
	KeyPair *KeyPair
}

// EcdsaSignatureLen is 64 bytes
const EcdsaSignatureLen = 64

var _ Signer = (*SignerSecp256k1)(nil)

// PublicKey returns the PublicKey of the signer
func (s *SignerSecp256k1) PublicKey() *types.PublicKey {
	return s.KeyPair.PublicKey
}

// Sign arbitrary payloads using a KeyPair
func (s *SignerSecp256k1) Sign(
	payload *types.SigningPayload,
	sigType types.SignatureType,
) (*types.Signature, error) {
	err := s.KeyPair.IsValid()
	if err != nil {
		return nil, err
	}
	privKeyBytes := s.KeyPair.PrivateKey

	if !(payload.SignatureType == sigType || payload.SignatureType == "") {
		return nil, fmt.Errorf("sign: invalid payload signaturetype %v", payload.SignatureType)
	}

	var sig []byte
	switch sigType {
	case types.EcdsaRecovery:
		sig, err = secp256k1.Sign(payload.Bytes, privKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("sign: unable to sign. %w", err)
		}
	case types.Ecdsa:
		sig, err = secp256k1.Sign(payload.Bytes, privKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("sign: unable to sign. %w", err)
		}
		sig = sig[:EcdsaSignatureLen]
	case types.Schnorr1:
		fmt.Printf("payload is %v\n\n", payload.Bytes)
		var unsignedTxnJson map[string]interface{}
		err := json.Unmarshal(payload.Bytes, &unsignedTxnJson)

		if err != nil {
			return nil, fmt.Errorf("sign: unable to convert unsigned transaction json. %w", err)
		}

		fmt.Printf("private key: %v\n\n", zilUtil.EncodeHex(privKeyBytes))
		fmt.Printf("unsigned txn json: %v\n\n", unsignedTxnJson)

		pubKeyBytes := s.KeyPair.PublicKey.Bytes

		toAddr, _ := zilBech32.FromBech32Addr(unsignedTxnJson["toAddr"].(string))

		zilliqaTransaction := &transaction.Transaction{
			Version:      fmt.Sprintf("%.0f", unsignedTxnJson["version"]),
			Nonce:        fmt.Sprintf("%.0f", unsignedTxnJson["nonce"]),
			Amount:       fmt.Sprintf("%.0f", unsignedTxnJson["amount"]),
			GasPrice:     fmt.Sprintf("%.0f", unsignedTxnJson["gasPrice"]),
			GasLimit:     fmt.Sprintf("%.0f", unsignedTxnJson["gasLimit"]),
			ToAddr:       toAddr,
			SenderPubKey: zilUtil.EncodeHex(pubKeyBytes),
			Code:         unsignedTxnJson["code"].(string),
			Data:         unsignedTxnJson["data"].(string),
		}

		zilliqaTransactionBytes, err := zilliqaTransaction.Bytes()
		if err != nil {
			return nil, fmt.Errorf("sign: unable to convert zilliqa transaction object to bytes %w", err)
		}

		sig, err = zilSchnorr.SignMessage(privKeyBytes, pubKeyBytes, zilliqaTransactionBytes)
		if err != nil {
			return nil, fmt.Errorf("sign: unable to sign. %w", err)
		}
	default:
		return nil, fmt.Errorf("sign: unsupported signature type. %w", err)
	}

	return &types.Signature{
		SigningPayload: payload,
		PublicKey:      s.KeyPair.PublicKey,
		SignatureType:  payload.SignatureType,
		Bytes:          sig,
	}, nil
}

// Verify verifies a Signature, by checking the validity of a Signature,
// the SigningPayload, and the PublicKey of the Signature.
func (s *SignerSecp256k1) Verify(signature *types.Signature) error {
	pubKey := signature.PublicKey.Bytes
	message := signature.SigningPayload.Bytes
	sig := signature.Bytes

	err := asserter.Signatures([]*types.Signature{signature})
	if err != nil {
		return err
	}

	var verify bool
	switch signature.SignatureType {
	case types.Ecdsa:
		verify = secp256k1.VerifySignature(pubKey, message, sig)
	case types.EcdsaRecovery:
		normalizedSig := sig[:EcdsaSignatureLen]
		verify = secp256k1.VerifySignature(pubKey, message, normalizedSig)
	case types.Schnorr1:
		var signedTxnJson map[string]interface{}
		err := json.Unmarshal(message, &signedTxnJson)

		if err != nil {
			return fmt.Errorf("sign: unable to convert signed transaction json. %w", err)
		}

		fmt.Printf("signed txn json: %v\n\n", signedTxnJson)

		toAddr, _ := zilBech32.FromBech32Addr(signedTxnJson["toAddr"].(string))

		zilliqaTransaction := &transaction.Transaction{
			Version:      fmt.Sprintf("%.0f", signedTxnJson["version"]),
			Nonce:        fmt.Sprintf("%.0f", signedTxnJson["nonce"]),
			Amount:       fmt.Sprintf("%.0f", signedTxnJson["amount"]),
			GasPrice:     fmt.Sprintf("%.0f", signedTxnJson["gasPrice"]),
			GasLimit:     fmt.Sprintf("%.0f", signedTxnJson["gasLimit"]),
			ToAddr:       toAddr,
			SenderPubKey: zilUtil.EncodeHex(pubKey),
			Code:         signedTxnJson["code"].(string),
			Data:         signedTxnJson["data"].(string),
		}

		zilliqaTransactionBytes, err := zilliqaTransaction.Bytes()
		if err != nil {
			return fmt.Errorf("sign: unable to convert zilliqa transaction object to bytes %w", err)
		}

		verify = zilSchnorr.VerifySignature(pubKey, zilliqaTransactionBytes, sig)

		fmt.Printf("result of verify: %v\n\n", verify)
	default:
		return fmt.Errorf("%s is not supported", signature.SignatureType)
	}

	if !verify {
		return errors.New("verify: verify returned false")
	}
	return nil
}
