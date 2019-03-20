package gm

import (
	"crypto/elliptic"
	"strings"

	"github.com/cjfoc/gmsm/sm2"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/utils"
)

const (
	privateKeyFlag = true
	publicKeyFlag  = false

	sm4value  = 0
	des3value = 1
	aesvalue  = 2
)

// var (
// 	PIN      = "123456"
// 	bigone   = new(big.Int).SetInt64(1)
// 	id_ctr   = new(big.Int)
// 	id_mutex sync.Mutex
// )

// func nextIDCtr() *big.Int {
// 	id_mutex.Lock()
// 	id_ctr = new(big.Int).Add(id_ctr, bigone)
// 	id_mutex.Unlock()
// 	return id_ctr
// }

// func loadLib(pin string) (*pkcs11go.Ctx, uint, *pkcs11go.SessionHandle, error) {
// 	var slot uint = 0
// 	logger.Debugf("Loading pkcs11go library \n")

// 	p11, err := pkcs11go.NewCtx()
// 	if err != nil {
// 		return nil, slot, nil, fmt.Errorf("Instantiate failed %v", err)
// 	}

// 	ctx := p11.PkcsCtx

// 	session, err := p11.NewSession()
// 	if err != nil {
// 		ctx.CloseSession(session)
// 		ctx.ClosePkcs()
// 		return nil, slot, nil, fmt.Errorf("getSession failed [%v]", err)
// 	}

// 	if err != nil {
// 		logger.Fatalf("OpenSession [%s]\n", err)
// 	}
// 	logger.Debugf("Created new pkcs11go session %+v on slot %d\n", session, slot)

// 	if pin == "" {
// 		return nil, slot, nil, fmt.Errorf("No PIN set\n")
// 	}
// 	slot = p11.Session
// 	return ctx, slot, &session, nil
// }

// func (csp *impl) getSession() (session pkcs11go.SessionHandle) {
// 	select {
// 	case session = <-csp.sessions:
// 		// logger.Debugf("Reusing existing pkcs11go session %+v on slot %d\n", session, csp.slot)

// 	default:
// 		// cache is empty (or completely in use), create a new session
// 		var s pkcs11go.SessionHandle
// 		var err error = nil
// 		for i := 0; i < 10; i++ {
// 			s, err = csp.ctx.OpenSession(csp.slot, pkcs11go.CKF_SERIAL_SESSION|pkcs11go.CKF_RW_SESSION)
// 			if err != nil {
// 				logger.Warningf("OpenSession failed, retrying [%s]\n", err)
// 			} else {
// 				break
// 			}
// 		}
// 		if err != nil {
// 			panic(fmt.Errorf("OpenSession failed [%s]\n", err))
// 		}
// 		logger.Debugf("Created new pkcs11go session %+v on slot %d\n", s, csp.slot)
// 		session = s
// 	}
// 	return session
// }

// func (csp *impl) returnSession(session pkcs11go.SessionHandle) {
// 	select {
// 	case csp.sessions <- session:
// 		// returned session back to session cache
// 	default:
// 		// have plenty of sessions in cache, dropping
// 		csp.ctx.CloseSession(session)
// 	}
// }

// func FindSymmetricObjectHandle(ctx *pkcs11go.Ctx, session pkcs11go.SessionHandle, algo uint, key, label []byte) (pkcs11go.ObjectHandle, error) {
// 	if key != nil {
// 		pk := pkcs11go.SetSymmetricPrivateKey(algo, key)
// 		return ctx.CreateObjectData(session, pk)
// 	} else if label != nil {
// 		template := []*pkcs11go.Attribute{
// 			pkcs11go.NewAttribute(pkcs11go.CKA_LABEL, string(label)),
// 		}
// 		return ctx.FindObjectByLabel(session, template)
// 	}

// 	return 0, errors.New("key and label is nil")
// }

// // rsa pkcs11go object
// func FindRSA2ObjectHandle(ctx *pkcs11go.Ctx, session pkcs11go.SessionHandle, ispriv bool, key interface{}, label []byte) (pkcs11go.ObjectHandle, error) {

// 	if key != nil {
// 		var attr []*pkcs11go.Attribute
// 		if ispriv {
// 			v := key.(*rsaPrivateKey)

// 			attr = pkcs11go.SetRSAPrivateKeyAttr(v.privKey.N.Bytes(), v.privKey.D.Bytes(), new(big.Int).SetInt64(int64(v.privKey.E)).Bytes(),
// 				v.privKey.Primes[0].Bytes(), v.privKey.Primes[1].Bytes(), v.privKey.Precomputed.Dp.Bytes(), v.privKey.Precomputed.Dq.Bytes(),
// 				nil)

// 		} else {
// 			v := key.(*rsaPublicKey)

// 			attr = pkcs11go.SetRSAPublicKeyAttr(v.pub.N.Bytes(), new(big.Int).SetInt64(int64(v.pub.E)).Bytes())
// 		}

// 		return ctx.CreateObjectData(session, attr)

// 	} else {

// 		class := pkcs11go.CKO_PRIVATE_KEY
// 		if !ispriv {
// 			class = pkcs11go.CKO_PUBLIC_KEY
// 		}
// 		template := []*pkcs11go.Attribute{
// 			pkcs11go.NewAttribute(pkcs11go.CKA_LABEL, string(label)),
// 			pkcs11go.NewAttribute(pkcs11go.CKA_CLASS, class),
// 		}

// 		return ctx.FindObjectByLabel(session, template)
// 	}

// 	return 0, errors.New("key  is nil")
// }

// // sm2 pkcs11go object
// func FindSM2ObjectHandle(ctx *pkcs11go.Ctx, session pkcs11go.SessionHandle, ispriv bool, key interface{}, label []byte) (pkcs11go.ObjectHandle, error) {

// 	if key != nil {

// 		var attr []*pkcs11go.Attribute
// 		if ispriv {
// 			v := key.(*ecdsaPrivateKey)

// 			ecpoint := []byte{0x04, 0x41, 0x04}
// 			ecpoint = append(ecpoint, v.privKey.X.Bytes()...)
// 			ecpoint = append(ecpoint, v.privKey.Y.Bytes()...)

// 			attr = pkcs11go.SetSM2PrivateKeyAttr(v.privKey.D.Bytes(), ecpoint)

// 		} else {
// 			v := key.(*ecdsaPublicKey)

// 			ecpoint := []byte{0x04, 0x41, 0x04}
// 			ecpoint = append(ecpoint, v.pub.X.Bytes()...)
// 			ecpoint = append(ecpoint, v.pub.Y.Bytes()...)

// 			attr = pkcs11go.SetSM2PublicKeyAttr(ecpoint)
// 		}

// 		return ctx.CreateObjectData(session, attr)

// 	} else {

// 		class := pkcs11go.CKO_PRIVATE_KEY
// 		if !ispriv {
// 			class = pkcs11go.CKO_PUBLIC_KEY
// 		}
// 		template := []*pkcs11go.Attribute{
// 			pkcs11go.NewAttribute(pkcs11go.CKA_LABEL, string(label)),
// 			pkcs11go.NewAttribute(pkcs11go.CKA_CLASS, class),
// 		}

// 		return ctx.FindObjectByLabel(session, template)
// 	}

// 	return 0, errors.New("key  is nil")
// }

// // ECC pkcs11go object
// func FindECCObjectHandle(ctx *pkcs11go.Ctx, session pkcs11go.SessionHandle, ispriv bool, key interface{}, label []byte) (pkcs11go.ObjectHandle, error) {

// 	if key != nil {

// 		var attr []*pkcs11go.Attribute
// 		if ispriv {
// 			v := key.(*eccPrivateKey)

// 			ecpoint := []byte{0x04, 0x41, 0x04}
// 			ecpoint = append(ecpoint, v.privKey.X.Bytes()...)
// 			ecpoint = append(ecpoint, v.privKey.Y.Bytes()...)

// 			attr = pkcs11go.SetECCPrivateKeyAttr(v.privKey.D.Bytes(), ecpoint)

// 		} else {
// 			v := key.(*eccPublicKey)

// 			ecpoint := []byte{0x04, 0x41, 0x04}
// 			ecpoint = append(ecpoint, v.pub.X.Bytes()...)
// 			ecpoint = append(ecpoint, v.pub.Y.Bytes()...)

// 			attr = pkcs11go.SetECCPublicKeyAttr(ecpoint)
// 		}

// 		return ctx.CreateObjectData(session, attr)

// 	} else {

// 		class := pkcs11go.CKO_PRIVATE_KEY
// 		if !ispriv {
// 			class = pkcs11go.CKO_PUBLIC_KEY
// 		}
// 		template := []*pkcs11go.Attribute{
// 			pkcs11go.NewAttribute(pkcs11go.CKA_LABEL, string(label)),
// 			pkcs11go.NewAttribute(pkcs11go.CKA_CLASS, class),
// 		}

// 		return ctx.FindObjectByLabel(session, template)
// 	}

// 	return 0, errors.New("key  is nil")
// }

// //pkcs11转 sm2
// func ObjectHandle2SM2(ispriv bool, el elliptic.Curve, value, ecpoint, lab []byte, sensitive bool) (interface{}, error) {

// 	if ecpoint == nil || len(ecpoint) == 0 {
// 		return nil, errors.New("ecpoint is nil")
// 	}

// 	// 转换ecdsa后进行签名签名验签
// 	// ----------------------读取数据转换成标准格式
// 	//固定值 044104
// 	//x acf8504fe3847d6d510776783caa18fcfc7ab1eb7db2edf58e42a90f89979298
// 	//y ce2cec135d523ef3cf687947509cce445bf720d55b13716bfadbeb9ce0f7f223

// 	x := new(big.Int).SetBytes(ecpoint[3 : 3+(len(ecpoint[3:]))/2])
// 	y := new(big.Int).SetBytes(ecpoint[3+(len(ecpoint[3:]))/2:])

// 	pk := &ecdsaPublicKey{
// 		label: lab,
// 		pub: &sm2.PublicKey{
// 			el,
// 			x,
// 			y,
// 		},
// 	}

// 	if ispriv {
// 		sk := &ecdsaPrivateKey{
// 			label:     lab,
// 			sensitive: sensitive,
// 			privKey: &sm2.PrivateKey{
// 				*pk.pub,
// 				new(big.Int).SetBytes(value),
// 			},
// 		}
// 		return sk, nil
// 	}

// 	return pk, nil
// }

// //pkcs11转 rsa
// func ObjectHandle2RSA(ispriv bool, modulus, priExponent, pubExponent, prime1, prime2, exponent1, exponent2, coefficient []byte, lab []byte, sensitive bool) (interface{}, error) {

// 	if modulus == nil || len(modulus) == 0 || pubExponent == nil || len(pubExponent) == 0 {
// 		return nil, errors.New("invalid param")
// 	}

// 	pk := &rsaPublicKey{
// 		label: lab,
// 		pub: &rsa.PublicKey{
// 			N: new(big.Int).SetBytes(modulus),
// 			E: int(new(big.Int).SetBytes(pubExponent).Int64()),
// 		},
// 	}

// 	if ispriv {
// 		var (
// 			prime    []*big.Int
// 			exponent rsa.PrecomputedValues
// 		)
// 		prime = append(prime, new(big.Int).SetBytes(prime1), new(big.Int).SetBytes(prime2))

// 		exponent.Dp = new(big.Int).SetBytes(exponent1)
// 		exponent.Dq = new(big.Int).SetBytes(exponent2)
// 		exponent.Qinv = new(big.Int).SetBytes(coefficient)

// 		sk := &rsaPrivateKey{
// 			label:     lab,
// 			sensitive: sensitive,
// 			privKey: &rsa.PrivateKey{
// 				*pk.pub,
// 				new(big.Int).SetBytes(priExponent),
// 				prime,
// 				exponent,
// 			},
// 		}

// 		return sk, nil
// 	}

// 	return pk, nil
// }

// //pkcs11转 ECC
// func ObjectHandle2ECC(ispriv bool, el elliptic.Curve, value, ecpoint, lab []byte, sensitive bool) (interface{}, error) {

// 	if ecpoint == nil || len(ecpoint) == 0 {
// 		return nil, errors.New("ecpoint is nil")
// 	}

// 	// 转换ecdsa后进行签名签名验签
// 	// ----------------------读取数据转换成标准格式
// 	//固定值 044104
// 	//x acf8504fe3847d6d510776783caa18fcfc7ab1eb7db2edf58e42a90f89979298
// 	//y ce2cec135d523ef3cf687947509cce445bf720d55b13716bfadbeb9ce0f7f223

// 	if len(ecpoint) < 67 {
// 		return nil, errors.New("ecpoint len is short")
// 	}
// 	x := new(big.Int).SetBytes(ecpoint[3 : 3+(len(ecpoint[3:]))/2])
// 	y := new(big.Int).SetBytes(ecpoint[3+(len(ecpoint[3:]))/2:])

// 	pk := eccPublicKey{
// 		label: lab,
// 		pub: &ecdsa.PublicKey{
// 			el,
// 			x,
// 			y,
// 		},
// 	}
// 	if !ispriv {
// 		return &pk, nil
// 	}
// 	sk := eccPrivateKey{
// 		label:     lab,
// 		sensitive: sensitive,
// 		privKey: &ecdsa.PrivateKey{
// 			*pk.pub,
// 			new(big.Int).SetBytes(value),
// 		},
// 	}
// 	return &sk, nil
// }

func GetPublicKey(priv bccsp.Key) (bccsp.Key, string, error) {

	var (
		pubKey    bccsp.Key
		err       error
		aglorithm string
	)

	lab, _ := priv.Label()
	algo := utils.GetAlgorithm()
	//私钥没有出加密机
	if algo != "SW" {
		if strings.HasPrefix(string(lab), "00") {
			pubKey, err = GetECDSAPublicKey(sm2.P256Sm2(), lab)
		} else if strings.HasPrefix(string(lab), "01") {
			pubKey, err = GetRSAPublicKey(lab)
		} else if strings.HasPrefix(string(lab), "02") {
			pubKey, err = GetECCPublicKey(elliptic.P256(), lab)
		}
	} else {
		// Marshall the bccsp public key as a crypto.PublicKey
		pubKey, err = priv.PublicKey()
	}
	if strings.HasPrefix(string(lab), "00") {
		aglorithm = "SM"
	} else if strings.HasPrefix(string(lab), "01") {
		aglorithm = "RSA"
	} else if strings.HasPrefix(string(lab), "02") {
		aglorithm = "ECC"
	} else {
		aglorithm = "SW"
	}
	return pubKey, aglorithm, err
}

//拼接数据 原始数据+标签+是否存储到加密机(0:key在本地 1:key在加密机)
func AppendByte(data, lab []byte, sen bool) []byte {

	v := data

	if sen {
		v = append(v, []byte("0"+string(lab))...)
	} else {
		v = append(v, []byte("1"+string(lab))...)
	}
	return v
}
