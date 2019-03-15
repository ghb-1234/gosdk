package sm4

import (
	"context"
	"fmt"

	"github.com/cjfoc/gmsm"
	"github.com/cjfoc/gmsm/pb"
)

type Key struct {
	subkeys   []byte
	Label     []byte
	Sensitive bool //true:存储在本地 false:存储在远端
}

func (key *Key) Decrypt(data []byte) ([]byte, error) {
	return Decrypt(key, data)
}

func (key *Key) Encrypt(data []byte) ([]byte, error) {
	return Encrypt(key, data)
}

func GenerateKey() (pubKey *Key, err error) {

	conn, err := gmsm.NewGrpcConn()
	if err != nil {
		return nil, fmt.Errorf("grpc newGrpcConn [%s]", err.Error())
	}

	defer conn.Close()

	client := pb.NewSm4OperateClient(conn)

	//生成key
	genlabel := pb.Sm4GenerateRequest{Ephemeral: false}
	genRes, err := client.Sm4Generate(context.Background(), &genlabel)
	if err != nil {
		return nil, fmt.Errorf("grpc [Sm4Generate]")
	}

	pubKey = &Key{subkeys: genRes.Value, Sensitive: false, Label: genRes.Label}

	return pubKey, nil
}

func Encrypt(key *Key, data []byte) ([]byte, error) {

	conn, err := gmsm.NewGrpcConn()
	if err != nil {
		return nil, fmt.Errorf("grpc newGrpcConn sm4Encrypt [%s]", err.Error())
	}

	defer conn.Close()

	client := pb.NewSm4OperateClient(conn)

	//加密
	enc := pb.Sm4EncryptRequest{Label: key.Label, Msg: data}
	encdata, err := client.Sm4EncryptData(context.Background(), &enc)
	if err != nil {
		return nil, fmt.Errorf("grpc Sm4EncryptData [%s]", err.Error())
	}

	return encdata.Dst, nil
}

func Decrypt(key *Key, data []byte) ([]byte, error) {

	conn, err := gmsm.NewGrpcConn()
	if err != nil {
		return nil, fmt.Errorf("grpc newGrpcConn sm4Decrypt [%s] ", err.Error())
	}

	defer conn.Close()

	client := pb.NewSm4OperateClient(conn)

	//解密
	enc := pb.Sm4DecryptRequest{Label: key.Label, Msg: data}
	encdata, err := client.Sm4DecryptData(context.Background(), &enc)
	if err != nil {
		return nil, fmt.Errorf("grpc [Sm4DecryptData] %s", err.Error())
	}

	return encdata.Dst, nil
}
