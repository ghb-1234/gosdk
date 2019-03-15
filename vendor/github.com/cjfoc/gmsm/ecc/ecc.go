package ecc

// reference to ecdsa
import (
	"context"
	"crypto"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/cjfoc/gmsm"
	"github.com/cjfoc/gmsm/pb"
)

var (
	default_uid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

type PublicKey struct {
	elliptic.Curve
	X, Y      *big.Int
	Label     []byte
	Sensitive bool //true:存储在本地 false:存储在远端
}

type PrivateKey struct {
	PublicKey
	D         *big.Int
	Label     []byte
	Sensitive bool //true:存储在本地 false:存储在远端
}

// The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *PrivateKey) Sign(msg []byte) ([]byte, error) {
	return EccSign(priv, msg)
}

func (priv *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	return Decrypt(priv, data)
}

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {
	ok, _ := EccVerify(pub, msg, sign)
	return ok
}

func (pub *PublicKey) Encrypt(data []byte) ([]byte, error) {
	return Encrypt(pub, data)
}

func GenerateKey() (*PrivateKey, error) {

	conn, err := gmsm.NewGrpcConn()
	if err != nil {
		return nil, fmt.Errorf("grpc newGrpcConn [%s]", err.Error())
	}

	defer conn.Close()

	client := pb.NewEccOperateClient(conn)

	//生成key
	genlabel := pb.EccGenerateRequest{Ephemeral: false}
	genRes, err := client.EccGenerate(context.Background(), &genlabel)
	if err != nil {
		return nil, fmt.Errorf("grpc [EccGenerate] [%s]", err.Error())
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = elliptic.P256()
	// priv.D = new(big.Int).SetBytes(genRes.D)
	priv.PublicKey.X, priv.PublicKey.Y = new(big.Int).SetBytes(genRes.X), new(big.Int).SetBytes(genRes.Y)
	priv.Label = genRes.Label
	priv.Sensitive = true

	return priv, nil

}

func EccSign(priv *PrivateKey, msg []byte) (signature []byte, err error) {

	conn, err := gmsm.NewGrpcConn()
	if err != nil {
		return nil, fmt.Errorf("signECDSA grpc newGrpcConn [%s]", err)
	}

	defer conn.Close()

	client := pb.NewEccOperateClient(conn)

	//签名
	sign := pb.EccSignRequest{Label: priv.Label, Msg: msg}
	signdata, err := client.EccSignData(context.Background(), &sign)
	if err != nil {
		return nil, fmt.Errorf("EccSignData [%s]", err)
	}

	return signdata.Dst, nil
}

func EccVerify(pub *PublicKey, msg, signature []byte) (bool, error) {

	conn, err := gmsm.NewGrpcConn()
	if err != nil {
		return false, fmt.Errorf("verifyECDSA grpc newGrpcConn [%s]", err)
	}

	defer conn.Close()

	client := pb.NewEccOperateClient(conn)

	//验签
	verify := pb.EccVerifyRequest{Label: pub.Label, Msg: msg, Dst: signature}
	verifydata, err := client.EccVerifyData(context.Background(), &verify)
	if err != nil {
		return false, fmt.Errorf("EccVerifyData [%s]", err)
	}
	return verifydata.Valid, nil

	//软验签
	// ecdsaSig := new(dsaSignature)
	// if rest, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
	// 	return false, err
	// } else if len(rest) != 0 {
	// 	return false, errors.New("x509: trailing data after ECC signature")
	// }
	// if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
	// 	return false, errors.New("x509: ECC signature contained zero or negative values")
	// }

	// sha := sha256.New()
	// sha.Write(msg)
	// msg1 := sha.Sum(nil)

	// if !ecdsa.Verify(key.pub, msg1, ecdsaSig.R, ecdsaSig.S) {
	// 	return false, errors.New("x509: ECC verification failure")
	// }
}

func Encrypt(pub *PublicKey, data []byte) ([]byte, error) {
	return nil, nil
}

func Decrypt(priv *PrivateKey, data []byte) ([]byte, error) {

	return nil, nil
}
