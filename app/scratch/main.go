package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	"github.com/ardanlabs/blockchain/foundation/blockchain/database"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type Tx struct {
	FromID string `json:"from"`  // Ethereum: Account sending the transaction. Will be checked against signature.
	ToID   string `json:"to"`    // Ethereum: Account receiving the benefit of the transaction.
	Value  uint64 `json:"value"` // Ethereum: Monetary value received from this transaction.
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	privateKey, err := crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		return fmt.Errorf("unable to load private key: %w", err)
	}

	tx := Tx{
		FromID: "Rodrigo",
		ToID:   "Bill",
		Value:  1,
	}
	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	stamp := []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))
	digestHash := crypto.Keccak256(stamp, data)

	sig, err := crypto.Sign(digestHash, privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign: %w", err)
	}

	fmt.Println("SIG:", hexutil.Encode(sig))

	v, r, s, err := ToVRSFromHexSignature(hexutil.Encode(sig))
	if err != nil {
		return fmt.Errorf("unable to get vrs from hex signature: %w", err)
	}

	fmt.Println("VRS:", v, r, s)

	//====================================================================================
	// OVER THE WIRE

	publicKey, err := crypto.SigToPub(digestHash, sig)
	if err != nil {
		return fmt.Errorf("unable to get pub key: %w", err)
	}

	fmt.Println("PUB:", crypto.PubkeyToAddress(*publicKey).String())

	//====================================================================================

	tx = Tx{
		FromID: "Rodrigo",
		ToID:   "Gates",
		Value:  1,
	}
	data, err = json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	stamp = []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))
	digestHash = crypto.Keccak256(stamp, data)

	sig, err = crypto.Sign(digestHash, privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign: %w", err)
	}

	fmt.Println("SIG:", hexutil.Encode(sig))

	//====================================================================================
	// OVER THE WIRE

	publicKey, err = crypto.SigToPub(digestHash, sig)
	if err != nil {
		return fmt.Errorf("unable to get pub key: %w", err)
	}

	fmt.Println("PUB:", crypto.PubkeyToAddress(*publicKey).String())

	//====================================================================================

	fmt.Println("=========================== TX ===========================")

	billTX, err := database.NewTx(1, 1, "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32", "0xdd6B972ffcc631a62CAE1BB9d80b7ff429c8ebA4", 100, 1, nil)
	if err != nil {
		return fmt.Errorf("unable to create bill tx: %w", err)
	}

	fmt.Println("BTX:", billTX)

	signedTX, err := billTX.Sign(privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign bill tx: %w", err)
	}

	fmt.Println("STX:", signedTX)

	return nil
}

func ToVRSFromHexSignature(sigStr string) (v, r, s *big.Int, err error) {
	sig, err := hex.DecodeString(sigStr[2:])
	if err != nil {
		return nil, nil, nil, err
	}

	r = big.NewInt(0).SetBytes(sig[:32])
	s = big.NewInt(0).SetBytes(sig[32:64])
	v = big.NewInt(0).SetBytes([]byte{sig[64]})

	return v, r, s, nil
}
