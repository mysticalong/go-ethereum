package poi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"os/user"
	"path"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/common"
)

var (
	ErrPCRQuoteInfo      = errors.New("PCR quote not match")
	ErrNotECPublicKey    = errors.New("Key is not a valid ECDSA public key")
	ErrNotECPrivateKey   = errors.New("Key is not a valid ECDSA private key")
	ErrMustBePEMEncoded  = errors.New("Not pem encoded")
	ErrECDSAVerification = errors.New("DSA Verification failed")
	ErrSignatureSize     = errors.New("Wrong Signature Size")
)

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func GetPubKeyBytes() ([]byte, error) {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	userHome := usr.HomeDir
	pcrPath := path.Join(userHome, ".pcr")
	if pcrthere, _ := exists(pcrPath); !pcrthere {
		log.Fatalf("no pcr folder exists!")
	}
	pubKeyPath := path.Join(pcrPath, "public.ecc.pem")
	key, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return nil, err
	}
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrMustBePEMEncoded
	}
	return block.Bytes, nil
}

func SignerFromPubKey(pubkey []byte) common.Address {
	log.Printf("Pubkey in SignerFromPubKey: %x", pubkey)
	tmp := sha3.Sum256(pubkey[:])
	bsigner := tmp[12:]
	signer := common.BytesToAddress(bsigner)
	return signer
}

func SignerFromSeal(seal []byte) common.Address {
	pubkey := seal[:pubkeyLength]
	return SignerFromPubKey(pubkey)
}

func TPMSign(hashToSign string) ([]byte, []byte, error) {
	log.Println("tpm signing", hashToSign)
	// defer flushPCR()
	args := strings.Split("-C 0x81010001 -G sha256 -L sha256:0,1,2,3,4,5,6,7,10,17,18 -f plain", " ")
	if hashToSign != "" {
		args = append(args, "-q")
		args = append(args, hashToSign)
	}
	// args = []string{"-h"}
	result, err := cmdWrapper("tpm2_quote", args...)
	if err != nil {
		// log.Fatal(err)
		return nil, nil, err
	}
	if result == nil || len(result) == 0 {
		// log.Fatal("signed nothing out.")
		return nil, nil, errors.New("PCR Error: signed nothing out.")
	}
	resultStr := string(result)
	// log.Println("\n", resultStr)
	end := strings.Index(resultStr, "signature:")
	quotedStr := resultStr[7:end]
	quotedStr = strings.TrimSpace(quotedStr)
	quoted, _ := hex.DecodeString(quotedStr)
	sigStr := resultStr[strings.Index(resultStr, "sig:")+4:]
	sigStr = strings.TrimSpace(sigStr)
	sig, _ := hex.DecodeString(sigStr)
	return quoted, sig, nil
}

func PCRVerify(quoted []byte, pcrs []string) error {
	//compare last 44 bytes
	//integraty that can be compared
	inpcr := quoted[(len(quoted) - 44):]
	// log.Printf("inpcr=%x, length=%d", inpcr, len(inpcr))
	for _, pcr := range pcrs {
		pcrValue, _ := hex.DecodeString(pcr)
		// log.Printf("pcr  =%x, length=%d", pcrValue, len(pcrValue))
		// log.Printf("String equals = %v", pcr == Hex(inpcr))
		if bytes.Equal(inpcr, pcrValue) {
			log.Println("PCRVerify success!")
			return nil
		}
	}
	return ErrPCRQuoteInfo
}

// Parse PEM encoded PKCS1 or PKCS8 public key
func ParseECPublicKeyFromBlockBytes(key []byte) (*ecdsa.PublicKey, error) {
	var err error

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(key); err != nil {
		return nil, err
	}

	var pkey *ecdsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return nil, ErrNotECPublicKey
	}

	return pkey, nil
}

func SignatureVerify(pubKey *ecdsa.PublicKey, signature []byte, quoted []byte) error {
	var esig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(signature, &esig); err != nil {
		log.Printf("error signature: %x", signature)
		return err
	}
	hash := sha256.Sum256(quoted)

	if !ecdsa.Verify(pubKey, hash[:], esig.R, esig.S) {
		return ErrECDSAVerification
	}
	log.Println("SignatureVerify success!")
	return nil
}
func cmdWrapper(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	opBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		return nil, err
	}
	// log.Println(string(opBytes))
	return opBytes, nil
}
func flushPCR() {
	_, err := cmdWrapper("tpm2_flushcontext", "-t")
	if err != nil {
		log.Println("Error tpm2_flushcontext", err)
		// } else {
		// 	Log.Debugln("tpm flush done.")
	}
}
