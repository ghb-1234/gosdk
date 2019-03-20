package gm

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"strings"

	x509 "github.com/cjfoc/gmx509"

	"github.com/cjfoc/gmsm/sm2"
	"github.com/pkg/errors"
)

func PEMtoDES3(raw []byte) ([]byte, []byte, error) {
	if len(raw) == 0 {
		return nil, nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, label := pem.Decode(raw)
	if block == nil && label == nil {
		return nil, nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	if block == nil && label != nil {
		return nil, label, nil
	}

	by, err := fileDecrypt(block.Bytes, des3value)
	if err != nil {
		return nil, nil, fmt.Errorf("PEMtoDES3 decrypt failed %v", err)
	}
	return by, label, nil
}

func Des3toEncryptedPEM(raw []byte, label []byte, sen bool) ([]byte, error) {
	if label == nil {
		return nil, errors.New("Invalid des3 key. It must be different from nil")
	}

	rawnew, err := fileEncrypt(raw, des3value)
	if err != nil {
		return nil, fmt.Errorf("Des3toEncryptedPEM encrypt failed %v", err)
	}

	b := pem.EncodeToMemory(&pem.Block{Type: "DES3 PRIVATE KEY", Bytes: rawnew})

	b = AppendByte(b, label, sen)

	return b, nil
}

func PEMtoSM4(raw []byte) ([]byte, []byte, error) {
	if len(raw) == 0 {
		return nil, nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, label := pem.Decode(raw)
	if block == nil && label == nil {
		return nil, nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	if block == nil && label != nil {
		return nil, label, nil
	}

	by, err := fileDecrypt(block.Bytes, sm4value)
	if err != nil {
		return nil, nil, fmt.Errorf("PEMtoSM4 decrypt failed %v", err)
	}
	return by, label, nil
}

func SM4toEncryptedPEM(raw []byte, label []byte, sen bool) ([]byte, error) {
	if label == nil {
		return nil, errors.New("Invalid sm4 key. It must be different from nil")
	}

	rawnew, err := fileEncrypt(raw, sm4value)
	if err != nil {
		return nil, fmt.Errorf("SM4toEncryptedPEM encrypt failed %v", err)
	}

	b := pem.EncodeToMemory(&pem.Block{Type: "SM4 PRIVATE KEY", Bytes: rawnew})

	b = AppendByte(b, label, sen)

	return b, nil
}

func PEMtoAES(raw []byte) ([]byte, []byte, error) {
	if len(raw) == 0 {
		return nil, nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, label := pem.Decode(raw)
	if block == nil && label == nil {
		return nil, nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	if block == nil && label != nil {
		return nil, label, nil
	}

	by, err := fileDecrypt(block.Bytes, aesvalue)
	if err != nil {
		return nil, nil, fmt.Errorf("PEMtoAES decrypt failed %v", err)
	}
	return by, label, nil
}

func AEStoEncryptedPEM(raw []byte, label []byte, sen bool) ([]byte, error) {
	if label == nil {
		return nil, errors.New("Invalid sm4 key. It must be different from nil")
	}

	rawnew, err := fileEncrypt(raw, aesvalue)
	if err != nil {
		return nil, fmt.Errorf("AEStoEncryptedPEM encrypt failed %v", err)
	}

	b := pem.EncodeToMemory(&pem.Block{Type: "AES PRIVATE KEY", Bytes: rawnew})

	b = AppendByte(b, label, sen)

	return b, nil
}

// PrivateKeyToEncryptedPEM converts a private key to an encrypted PEM
func PrivateKeyToEncryptedPEM(privateKey interface{}, label []byte, sen bool) ([]byte, error) {
	var (
		raw []byte
		err error
	)

	if privateKey == nil && label == nil {
		return nil, errors.New("Invalid private key. It must be different from nil.")
	}
	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:

		if k != nil {
			raw, err = x509.MarshalECPrivateKey(k)
			if err != nil {
				return nil, err
			}
		}

		rawnew, err := fileEncrypt(raw, aesvalue)
		if err != nil {
			return nil, fmt.Errorf("AEStoEncryptedPEM encrypt failed %v", err)
		}

		block := &pem.Block{
			Type:  "ECC PRIVATE KEY",
			Bytes: rawnew,
		}
		b := pem.EncodeToMemory(block)
		b = AppendByte(b, label, sen)

		return b, nil
	case *sm2.PrivateKey:
		if k != nil {
			raw, err = x509.MarshalSm2UnecryptedPrivateKey(k)
			if err != nil {
				return nil, err
			}
		}

		rawnew, err := fileEncrypt(raw, sm4value)
		if err != nil {
			return nil, fmt.Errorf("SM4toEncryptedPEM encrypt failed %v", err)
		}

		block := &pem.Block{
			Type:  "SM2 PRIVATE KEY",
			Bytes: rawnew,
		}
		b := pem.EncodeToMemory(block)
		b = AppendByte(b, label, sen)

		return b, nil
	case *rsa.PrivateKey:
		if k != nil {
			raw = x509.MarshalPKCS1PrivateKey(k)
		}

		rawnew, err := fileEncrypt(raw, des3value)
		if err != nil {
			return nil, fmt.Errorf("SM4toEncryptedPEM encrypt failed %v", err)
		}

		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: rawnew,
		}
		b := pem.EncodeToMemory(block)
		b = AppendByte(b, label, sen)

		return b, nil
	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PrivateKey")
	}
}

// DERToPrivateKey unmarshals a der to private key
func DERToPrivateKey(der []byte) (key interface{}, err error) {

	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(der, nil); err == nil {
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, *sm2.PrivateKey:
			return
		default:
			return nil, errors.New("Found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return
	}

	return nil, errors.New("Invalid key type. The DER must contain an rsa.PrivateKey or ecdsa.PrivateKey")
}

// PEMtoPrivateKey unmarshals a pem to private key
func PEMtoPrivateKey(raw []byte) (interface{}, []byte, error) {
	if len(raw) == 0 {
		return nil, nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, label := pem.Decode(raw)
	if block == nil && label == nil {
		return nil, nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}
	if block == nil && label != nil {
		return nil, label, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	var (
		rawnew []byte
		err    error
	)
	if !strings.Contains(string(label), "-") {
		pre := isSM(label)
		if pre == -1 {
			return nil, nil, fmt.Errorf("private key type is unknow")
		}

		rawnew, err = fileDecrypt(block.Bytes, pre)
		if err != nil {
			return nil, nil, err
		}
	} else {
		rawnew = block.Bytes
	}

	// label 1:key在加密机 0:key在本地保存
	if string(label[:1]) == "1" {
		return nil, label, nil
	}

	cert, err := DERToPrivateKey(rawnew)
	if err != nil {
		return nil, nil, err
	}
	return cert, label, err
}

// PublicKeyToEncryptedPEM converts a public key to encrypted pem
func PublicKeyToEncryptedPEM(publicKey interface{}, label []byte) ([]byte, error) {
	if publicKey == nil && label == nil {
		return nil, errors.New("Invalid public key. It must be different from nil.")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil.")
		}
		raw, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		rawnew, err := fileEncrypt(raw, sm4value)
		if err != nil {
			return nil, fmt.Errorf("SM4toEncryptedPEM encrypt failed %v", err)
		}

		block := &pem.Block{
			Type:  "ECC PUBLIC KEY",
			Bytes: rawnew,
		}
		v := pem.EncodeToMemory(block)
		v = append(v, label...)

		return v, nil
	case *rsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid rsa public key. It must be different from nil.")
		}
		raw, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		rawnew, err := fileEncrypt(raw, des3value)
		if err != nil {
			return nil, fmt.Errorf("SM4toEncryptedPEM encrypt failed %v", err)
		}

		block := &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: rawnew,
		}
		v := pem.EncodeToMemory(block)
		v = append(v, label...)
		return v, nil
	}

	return nil, errors.New("Invalid key type. It must be *ecdsa.PublicKey")
}

// PEMtoPublicKey unmarshals a pem to public key
func PEMtoPublicKey(raw []byte) (interface{}, []byte, error) {
	if len(raw) == 0 {
		return nil, nil, errors.New("Invalid PEM. It must be different from nil.")
	}

	block, label := pem.Decode(raw)
	if block == nil && label == nil {
		return nil, nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}
	if block == nil && label != nil {
		return nil, label, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	var (
		rawnew []byte
		err    error
	)
	if !strings.Contains(string(label), "-") {
		pre := isSM(label)
		if pre == -1 {
			return nil, nil, fmt.Errorf("public key type is unknow")
		}

		rawnew, err = fileDecrypt(block.Bytes, pre)
		if err != nil {
			return nil, nil, err
		}
	} else {
		rawnew = block.Bytes
	}

	cert, err := DERToPublicKey(rawnew)
	if err != nil {
		return nil, nil, err
	}
	return cert, label, err
}

// DERToPublicKey unmarshals a der to public key
func DERToPublicKey(raw []byte) (pub interface{}, err error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid DER. It must be different from nil.")
	}

	key, err := x509.ParseSm2PublicKey(raw)

	return key, err
}

func isSM(raw []byte) int {
	_, label := pem.Decode(raw)

	if strings.HasPrefix(string(label[1:]), "00") {
		return sm4value
	}
	if strings.HasPrefix(string(label[1:]), "01") {
		return des3value
	}
	if strings.HasPrefix(string(label[1:]), "02") {
		return aesvalue
	}
	return -1
}

func fileDecrypt(raw []byte, pre int) (rawnew []byte, err error) {
	//TODO
	// if pre == sm4value { //sm
	// 	rawnew, err = sm4Decrypt(nil, sm4Secret, raw)
	// } else if pre == des3value { //des3
	// 	rawnew, err = des3Decrypt(nil, des3Secret, raw)
	// } else if pre == aesvalue { //aes
	// 	rawnew, err = aesDecrypt(nil, aesSecret, raw)
	// }

	// if err != nil {
	// 	return nil, fmt.Errorf("fileEncrypt encrypt failed %v", err)
	// }
	// return
	return raw, nil
}

func fileEncrypt(raw []byte, pre int) (rawnew []byte, err error) {
	//TODO
	// if pre == sm4value { //sm
	// 	rawnew, err = sm4Encrypt(nil, sm4Secret, raw)
	// } else if pre == des3value { //des3
	// 	rawnew, err = des3Encrypt(nil, des3Secret, raw)
	// } else if pre == aesvalue{ //aes
	// 	rawnew, err = aesEncrypt(nil, aesSecret, raw)
	// }
	// if err != nil {
	// 	return nil, fmt.Errorf("fileEncrypt Encrypt failed %v", err)
	// }
	// return
	return raw, nil
}
