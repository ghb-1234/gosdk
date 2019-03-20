package sm2

// reference to ecdsa
import (
	"context"
	"crypto"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/cjfoc/gmsm"
	"github.com/cjfoc/gmsm/pb"
	"github.com/pkg/errors"
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
	return Sm2Sign(priv, msg)
}

func (priv *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	return Decrypt(priv, data)
}

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {
	return Sm2Verify(pub, msg, sign)
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

	client := pb.NewSm2OperateClient(conn)

	//生成key
	genlabel := pb.Sm2GenerateRequest{Ephemeral: false}
	genRes, err := client.Sm2Generate(context.Background(), &genlabel)
	if err != nil {
		return nil, fmt.Errorf("grpc [Sm2Generate] [%s]", err.Error())
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = P256Sm2()
	// priv.D = new(big.Int).SetBytes(genRes.D)
	priv.PublicKey.X, priv.PublicKey.Y = new(big.Int).SetBytes(genRes.X), new(big.Int).SetBytes(genRes.Y)
	priv.Label = genRes.Label
	priv.Sensitive = true

	return priv, nil

}

func Sm2Sign(priv *PrivateKey, msg []byte) (signature []byte, err error) {

	conn, err := gmsm.NewGrpcConn()
	if err != nil {
		return nil, fmt.Errorf("signECDSA grpc newGrpcConn [%s]", err)
	}

	defer conn.Close()

	client := pb.NewSm2OperateClient(conn)

	//签名
	sign := pb.Sm2SignRequest{Label: priv.Label, Msg: msg}
	signdata, err := client.Sm2SignData(context.Background(), &sign)
	if err != nil {
		return nil, fmt.Errorf("Sm2SignData [%s]", err)
	}

	return signdata.Dst, nil
}

func Sm2Verify(pub *PublicKey, msg, signature []byte) bool {

	conn, err := gmsm.NewGrpcConn()
	if err != nil {
		return false
	}

	defer conn.Close()

	client := pb.NewSm2OperateClient(conn)

	//验签
	verify := pb.Sm2VerifyRequest{Label: pub.Label, Msg: msg, Dst: signature}
	verifydata, err := client.Sm2VerifyData(context.Background(), &verify)
	if err != nil {
		return false
	}
	return verifydata.Valid
}

/*
 * sm2密文结构如下:
 *  x
 *  y
 *  hash
 *  CipherText
 */
func Encrypt(pub *PublicKey, data []byte) ([]byte, error) {
	return nil, nil
}

func Decrypt(priv *PrivateKey, data []byte) ([]byte, error) {

	return nil, nil
}

func GetPublicKey(label []byte) (*PublicKey, error) {

	conn, err := gmsm.NewGrpcConn()
	if err != nil {
		return nil, fmt.Errorf("grpc newGrpcConn [%s]", err.Error())
	}

	defer conn.Close()

	client := pb.NewSm2OperateClient(conn)

	//生成key
	req := pb.Sm2PublicKeyRequest{Label: label}
	genRes, err := client.Sm2PublicKey(context.Background(), &req)
	if err != nil {
		return nil, errors.WithMessage(err, "grpc [Sm2PublicKey]")
	}

	pub := &PublicKey{
		Curve:     P256Sm2(),
		X:         new(big.Int).SetBytes(genRes.X),
		Y:         new(big.Int).SetBytes(genRes.Y),
		Label:     label,
		Sensitive: true,
	}

	return pub, nil
}
