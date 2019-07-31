package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
	"math/big"

	"github.com/phjt-go/crypto/sha3"
)

var (
	// 返回的错误规范填充。
	errNegativeValue          = errors.New("value may be interpreted as negative")
	errExcessivelyPaddedValue = errors.New("value is excessively padded")

	// 用于调整ECDSA延展性的曲线顺序和halforder
	order     = new(big.Int).Set(S256().N)
	halforder = new(big.Int).Rsh(order, 1)

	// 用于RFC6979实现时测试nonce的正确性
	one = big.NewInt(1)

	// 用于用字节0x01填充字节片。这里提供它是为了避免多次创建它。
	oneInitializer = []byte{0x01}
)

// Signature 签名是一种表示ecdsa签名的类型
type Signature struct {
	R *big.Int
	S *big.Int
}

// Serialize 以更严格的DER格式返回ECDSA签名。注意，返回的序列化字节不包括在比特币签名脚本中使用的附加散列类型。
// 编码/asn1被破坏，所以我们手工滚动这个输出:0x30 <length> 0x02 <length r> r 0x02 <length s>
func (sig *Signature) Serialize() []byte {
	// low 'S' malleability breaker
	sigS := sig.S
	if sigS.Cmp(halforder) == 1 {
		sigS = new(big.Int).Sub(order, sigS)
	}
	rb := canonicalizeInt(sig.R)
	sb := canonicalizeInt(sigS)

	length := 6 + len(rb) + len(sb)
	b := make([]byte, length, length)

	b[0] = 0x30
	b[1] = byte(length - 2)
	b[2] = 0x02
	b[3] = byte(len(rb))
	offset := copy(b[4:], rb) + 4
	b[offset] = 0x02
	b[offset+1] = byte(len(sb))
	copy(b[offset+2:], sb)
	return b
}

// Verify 通过调用ecdsa的公钥来验证哈希的签名是否正确
func (sig *Signature) Verify(hash []byte, pubKey *PublicKey) bool {
	return ecdsa.Verify(pubKey.ToECDSA(), hash, sig.R, sig.S)
}

// canonicalizeInt返回经过必要调整的传递的整数的字节，以确保大尾数编码的整数不可能被误解为负数。
func canonicalizeInt(val *big.Int) []byte {
	b := val.Bytes()
	if len(b) == 0 {
		b = []byte{0x00}
	}
	if b[0]&0x80 != 0 {
		paddedBytes := make([]byte, len(b)+1)
		copy(paddedBytes[1:], b)
		b = paddedBytes
	}
	return b
}

// IsEqual 将此签名实例与传递的签名实例进行比较，如果两个签名相等，则返回true。
func (sig *Signature) IsEqual(otherSig *Signature) bool {
	return sig.R.Cmp(otherSig.R) == 0 && sig.S.Cmp(otherSig.S) == 0
}

/*// DER编码签名的最小长度
const minSigLen = 8

func parseSig(sigStr []byte, curve elliptic.Curve, der bool) (*Signature, error) {

	signature := &Signature{}

	if len(sigStr) < minSigLen {
		return nil, errors.New("malformed signature: too short")
	}
	// 0x30
	index := 0
	if sigStr[index] != 0x30 {
		return nil, errors.New("malformed signature: no header magic")
	}
	index++
	// 剩余信息长度
	siglen := sigStr[index]
	index++

	//siglen应该小于整个消息，而大于最小消息大小。
	if int(siglen+2) > len(sigStr) || int(siglen+2) < minSigLen {
		return nil, errors.New("malformed signature: bad length")
	}
	sigStr = sigStr[:siglen+2]

	if sigStr[index] != 0x02 {
		return nil,
			errors.New("malformed signature: no 1st int marker")
	}
	index++

	rLen := int(sigStr[index])
	index++
	if rLen <= 0 || rLen > len(sigStr)-index-3 {
		return nil, errors.New("malformed signature: bogus R length")
	}
	// Then R itself.
	rBytes := sigStr[index : index+rLen]
	if der {
		switch err := canonicalPadding(rBytes); err {
		case errNegativeValue:
			return nil, errors.New("signature R is negative")
		case errExcessivelyPaddedValue:
			return nil, errors.New("signature R is excessively padded")
		}
	}
	signature.R = new(big.Int).SetBytes(rBytes)
	index += rLen
	// 0x02. length already checked in previous if.
	if sigStr[index] != 0x02 {
		return nil, errors.New("malformed signature: no 2nd int marker")
	}
	index++

	sLen := int(sigStr[index])
	index++

	if sLen <= 0 || sLen > len(sigStr)-index {
		return nil, errors.New("malformed signature: bogus S length")
	}

	sBytes := sigStr[index : index+sLen]
	if der {
		switch err := canonicalPadding(sBytes); err {
		case errNegativeValue:
			return nil, errors.New("signature S is negative")
		case errExcessivelyPaddedValue:
			return nil, errors.New("signature S is excessively padded")
		}
	}
	signature.S = new(big.Int).SetBytes(sBytes)
	index += sLen

	if index != len(sigStr) {
		return nil, fmt.Errorf("malformed signature: bad final length %v != %v",
			index, len(sigStr))
	}

	// Verify也会检查这个，但是如果我们在这里验证的话，我们可以更确定我们解析正确。
	if signature.R.Sign() != 1 {
		return nil, errors.New("signature R isn't 1 or more")
	}
	if signature.S.Sign() != 1 {
		return nil, errors.New("signature S isn't 1 or more")
	}
	if signature.R.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("signature R is >= curve.N")
	}
	if signature.S.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("signature S is >= curve.N")
	}
	return signature, nil
}

// 将曲线类型“曲线”的BER格式签名解析为签名类型，完成一些基本的完整性检查。如果需要根据更严格的DER格式进行解析，请使用ParseDERSignature。
func ParseSignature(sigStr []byte, curve elliptic.Curve) (*Signature, error) {return parseSig(sigStr, curve, false)}

// 将曲线类型“曲线”的DER格式的签名解析为签名类型。如果需要根据不那么严格的BER格式进行解析，请使用ParseSignature。
func ParseDERSignature(sigStr []byte, curve elliptic.Curve) (*Signature, error) {return parseSig(sigStr, curve, true)}

// 检查大端编码整数是否可能被误解为负数(即使OpenSSL将所有数字视为无符号)，或者是否存在不必要的前导零填充。
func canonicalPadding(b []byte) error {
	switch {
	case b[0]&0x80 == 0x80:
		return errNegativeValue
	case len(b) > 1 && b[0] == 0x00 && b[1]&0x80 != 0x80:
		return errExcessivelyPaddedValue
	default:
		return nil
	}
}*/

// hashToInt将哈希值转换为整数
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// 从给定消息散列“msg”上的签名“sig”中提取公钥
func recoverKeyFromSignature(curve *KoblitzCurve, sig *Signature, msg []byte,
	iter int, doChecks bool) (*PublicKey, error) {

	Rx := new(big.Int).Mul(curve.Params().N,
		new(big.Int).SetInt64(int64(iter/2)))
	Rx.Add(Rx, sig.R)
	if Rx.Cmp(curve.Params().P) != -1 {
		return nil, errors.New("calculated Rx is larger than curve P")
	}

	Ry, err := decompressPoint(curve, Rx, iter%2 == 1)
	if err != nil {
		return nil, err
	}

	if doChecks {
		nRx, nRy := curve.ScalarMult(Rx, Ry, curve.Params().N.Bytes())
		if nRx.Sign() != 0 || nRy.Sign() != 0 {
			return nil, errors.New("n*R does not equal the point at infinity")
		}
	}

	e := hashToInt(msg, curve)

	invr := new(big.Int).ModInverse(sig.R, curve.Params().N)

	invrS := new(big.Int).Mul(invr, sig.S)
	invrS.Mod(invrS, curve.Params().N)
	sRx, sRy := curve.ScalarMult(Rx, Ry, invrS.Bytes())

	e.Neg(e)
	e.Mod(e, curve.Params().N)
	e.Mul(e, invr)
	e.Mod(e, curve.Params().N)
	minuseGx, minuseGy := curve.ScalarBaseMult(e.Bytes())

	Qx, Qy := curve.Add(sRx, sRy, minuseGx, minuseGy)

	return &PublicKey{
		Curve: curve,
		X:     Qx,
		Y:     Qy,
	}, nil
}

// SignCompact 使用指定的koblitz曲线上的指定私钥从而在散列中生成数据的压缩签名。
func SignCompact(curve *KoblitzCurve, key *PrivateKey,
	hash []byte, isCompressedKey bool) ([]byte, error) {
	sig, err := key.Sign(hash)
	if err != nil {
		return nil, err
	}

	// bitcoind检查R和S的位长。ecdsa签名算法返回R和S mod N，因此它们是曲线的位大小，因此大小正确。
	for i := 0; i < (curve.H+1)*2; i++ {
		pk, err := recoverKeyFromSignature(curve, sig, hash, i, true)
		if err == nil && pk.X.Cmp(key.X) == 0 && pk.Y.Cmp(key.Y) == 0 {
			result := make([]byte, 1, 2*curve.byteSize+1)
			result[0] = 27 + byte(i)
			if isCompressedKey {
				result[0] += 4
			}

			curvelen := (curve.BitSize + 7) / 8

			bytelen := (sig.R.BitLen() + 7) / 8
			if bytelen < curvelen {
				result = append(result,
					make([]byte, curvelen-bytelen)...)
			}
			result = append(result, sig.R.Bytes()...)

			bytelen = (sig.S.BitLen() + 7) / 8
			if bytelen < curvelen {
				result = append(result,
					make([]byte, curvelen-bytelen)...)
			}
			result = append(result, sig.S.Bytes()...)

			return result, nil
		}
	}

	return nil, errors.New("no valid solution for pubkey found")
}

// RecoverCompact 验证了“曲线”中Koblitz曲线的“哈希”的“压缩签名”。如果签名匹配，则返回恢复的公钥;如果原始密钥压缩或未压缩，则返回boolen，否则将返回错误。
func RecoverCompact(curve *KoblitzCurve, signature, hash []byte) (*PublicKey, bool, error) {
	bitlen := (curve.BitSize + 7) / 8
	if len(signature) != 1+bitlen*2 {
		return nil, false, errors.New("invalid compact signature size")
	}

	iteration := int((signature[0] - 27) & ^byte(4))

	sig := &Signature{
		R: new(big.Int).SetBytes(signature[1 : bitlen+1]),
		S: new(big.Int).SetBytes(signature[bitlen+1:]),
	}
	key, err := recoverKeyFromSignature(curve, sig, hash, iteration, false)
	if err != nil {
		return nil, false, err
	}

	return key, ((signature[0] - 27) & 4) == 4, nil
}

// 生成一个ECDSA nonce (' k ')。它以一个32字节的散列作为输入，并立即返回32字节，以便在ECDSA算法中使用。
func nonceRFC6979(privkey *big.Int, hash []byte) *big.Int {

	curve := S256()
	q := curve.Params().N
	x := privkey
	alg := sha256.New

	qlen := q.BitLen()
	holen := alg().Size()
	rolen := (qlen + 7) >> 3
	bx := append(int2octets(x, rolen), bits2octets(hash, curve, rolen)...)

	v := bytes.Repeat(oneInitializer, holen)

	// Go将所有分配的内存归零
	k := make([]byte, holen)

	k = mac(alg, k, append(append(v, 0x00), bx...))

	v = mac(alg, k, v)

	k = mac(alg, k, append(append(v, 0x01), bx...))

	v = mac(alg, k, v)

	for {
		var t []byte

		for len(t)*8 < qlen {
			v = mac(alg, k, v)
			t = append(t, v...)
		}

		secret := hashToInt(t, curve)
		if secret.Cmp(one) >= 0 && secret.Cmp(q) < 0 {
			return secret
		}
		k = mac(alg, k, append(v, 0x00))
		v = mac(alg, k, v)
	}
}

// signRFC6979根据RFC6979和BIP 62生成一个确定的ECDSA签名
func signRFC6979(privateKey *PrivateKey, hash []byte) (*Signature, error) {

	privkey := privateKey
	N := order
	k := nonceRFC6979(privkey.D, hash)
	inv := new(big.Int).ModInverse(k, N)
	r, _ := privkey.Curve.ScalarBaseMult(k.Bytes())
	if r.Cmp(N) == 1 {
		r.Sub(r, N)
	}

	if r.Sign() == 0 {
		return nil, errors.New("calculated R is zero")
	}

	e := hashToInt(hash, privkey.Curve)
	s := new(big.Int).Mul(privkey.D, r)
	s.Add(s, e)
	s.Mul(s, inv)
	s.Mod(s, N)

	if s.Cmp(halforder) == 1 {
		s.Sub(N, s)
	}
	if s.Sign() == 0 {
		return nil, errors.New("calculated S is zero")
	}
	return &Signature{R: r, S: s}, nil
}

// mac返回给定键和消息的HMAC。
func mac(alg func() hash.Hash, k, m []byte) []byte {
	h := hmac.New(alg, k)
	h.Write(m)
	return h.Sum(nil)
}

func int2octets(v *big.Int, rolen int) []byte {
	out := v.Bytes()

	// left pad with zeros if it's too short
	if len(out) < rolen {
		out2 := make([]byte, rolen)
		copy(out2[rolen-len(out):], out)
		return out2
	}

	// drop most significant bytes if it's too long
	if len(out) > rolen {
		out2 := make([]byte, rolen)
		copy(out2, out[len(out)-rolen:])
		return out2
	}

	return out
}

func bits2octets(in []byte, curve elliptic.Curve, rolen int) []byte {
	z1 := hashToInt(in, curve)
	z2 := new(big.Int).Sub(z1, curve.Params().N)
	if z2.Sign() < 0 {
		return int2octets(z1, rolen)
	}
	return int2octets(z2, rolen)
}

// SignAddress 签名地址
func SignAddress(address Address, privateKey *PrivateKey) ([]byte, error) {

	hash := sha3.Keccak256(address[:])
	sign, err := SignCompact(S256(), privateKey, hash[:], true) //私钥加签
	if err != nil {
		return nil, err
	}

	return sign, nil
}

// PrvKeySign 节点私钥加签
func PrvKeySign(prvKey string, hash []byte) ([]byte, error) {

	// 字符串转私钥
	privateKey, err := HexToECDSA(prvKey)
	if err != nil {
		return nil, err
	}

	// 私钥签名(压缩版)
	signature, err := SignCompact(S256(), privateKey, hash, true)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// PubKeyCheckSign 公钥验签
func PubKeyCheckSign(signatrue []byte, hash []byte, pubKeyStr string) (bool, error) {

	// 签名获取公钥
	pub, err := SignToPubKey(signatrue, hash)
	if err != nil {
		return false, err
	}

	// 公钥转66哈希字符串
	hexPubKey := PubKeyToHex(pub)

	// 两相对比
	if hexPubKey == pubKeyStr {
		return true, nil
	}
	return false, errors.New("Attestation of failure. ")
}

// SignToPubKey 签名换公钥
func SignToPubKey(signature, hash []byte) (*PublicKey, error) {
	pub, _, err := RecoverCompact(S256(), signature, hash)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
