package ecdsa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/phjt-go/crypto/rlp"
	"github.com/phjt-go/crypto/sha2"
	"github.com/phjt-go/crypto/sha3"
	"github.com/phjt-go/util/conv"
	"github.com/phjt-go/util/math"
	"io"
	"math/big"
	"time"
)

var (
	runMode  string
	randKey  string
	randSign string
	prv      *PrivateKey
	puk      PublicKey
	curve    elliptic.Curve

	// 解密过程中，当消息验证检查(MAC)失败时，发生ErrInvalidMAC。这是因为无效的私钥或损坏的密文。
	errInvalidMAC = errors.New("invalid mac hash")
	// errInputTooShort发生在解密函数的输入密文长度小于134字节的情况下。
	errInputTooShort = errors.New("ciphertext too short")
	// errUnsupportedCurve发生在加密文本的前两个字节不是0x02CA (= 712 = secp256k1，来自OpenSSL)的时候。
	errUnsupportedCurve = errors.New("unsupported curve")
	errInvalidXLength   = errors.New("invalid X length, must be 32")
	errInvalidYLength   = errors.New("invalid Y length, must be 32")
	errInvalidPadding   = errors.New("invalid PKCS#7 padding")

	ciphCurveBytes  = [2]byte{0x02, 0xCA}
	ciphCoordLength = [2]byte{0x00, 0x20}
)

// PrivateKey 私钥包装ecdsa。作为一种方便，PrivateKey主要用于用私钥签名，而无需直接导入ecdsa包
type PrivateKey ecdsa.PrivateKey

// GenerateSharedSecret 基于私钥和公钥生成共享密钥。
func GenerateSharedSecret(privkey *PrivateKey, pubkey *PublicKey) []byte {
	x, _ := pubkey.Curve.ScalarMult(pubkey.X, pubkey.Y, privkey.D.Bytes())
	return x.Bytes()
}

// PrivKeyFromBytes 根据私钥和参数返回“curve”的私钥和公钥 。
func PrivKeyFromBytes(curve elliptic.Curve, pk []byte) (*PrivateKey, *PublicKey) {
	x, y := curve.ScalarBaseMult(pk)

	priv := &PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(pk),
	}

	return priv, (*PublicKey)(&priv.PublicKey)
}

// PubKey 返回与此私钥对应的公钥。
func (p *PrivateKey) PubKey() *PublicKey {
	return (*PublicKey)(&p.PublicKey)
}

// Sign 使用私钥为提供的散列(应该是散列较大消息的结果)生成ECDSA签名。生成的签名是确定性的(相同的消息和相同的密钥生成相同的签名)，并且符合RFC6979和BIP0062的规范。
func (p *PrivateKey) Sign(hash []byte) (*Signature, error) {
	return signRFC6979(p, hash)
}

const (
	pubkeyCompressed   byte = 0x2 // y_bit + x coord
	pubkeyUncompressed byte = 0x4 // x coord + y coord
	pubkeyHybrid       byte = 0x6 // y_bit + x coord + y coord
	size                    = 65  // 长度

	// PubKeyBytesLenCompressed 序列化公钥的33为长度。
	PubKeyBytesLenCompressed = 33

	// PubKeyBytesLenUncompressed 序列化公钥的长度。
	PubKeyBytesLenUncompressed = 65

	// PubKeyBytesLenHybrid 序列化公钥的长度。
	PubKeyBytesLenHybrid = 65

	// PrivKeyBytesLen 定义序列化私钥的字节长度。
	PrivKeyBytesLen = 32
)

// Serialize 返回私钥编号d，它是一个大端二进制编码的数字，填充长度为32字节。
func (p *PrivateKey) Serialize() []byte {
	b := make([]byte, 0, PrivKeyBytesLen)
	return paddedAppend(PrivKeyBytesLen, b, p.D.Bytes())
}

// PubKeyToHex 公钥转哈希字符串
func PubKeyToHex(pubKey *PublicKey) string {

	// 将公钥序列化为65位非压缩
	unCompress := pubKey.SerializeUncompressed()

	// 将Byte类型65位非压缩转哈希字符串
	return hex.EncodeToString(unCompress)
}

// HexToPubKey 哈希字符串转公钥
func HexToPubKey(hexPub string) (*PublicKey, error) {
	pubKey, err := HexToECDSAPub(hexPub)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// HexToPrvKey 哈希转私钥
func PrvKeyToHex(prvKey *PrivateKey) string {
	return hex.EncodeToString(FromECDSA(prvKey))
}

// HexToPrvKey 哈希转私钥
func HexToPrvKey(hexPrvKey string) (*PrivateKey, error) {
	prv, err := HexToECDSA(hexPrvKey)
	if err != nil {
		return nil, err
	}
	return prv, nil
}

// Decrypt 解密使用加密函数加密的数据。
func Decrypt(priv *PrivateKey, in []byte) ([]byte, error) {
	// IV + Curve params/X/Y + 1 block + HMAC-256
	if len(in) < aes.BlockSize+70+aes.BlockSize+sha256.Size {
		return nil, errInputTooShort
	}

	// read iv
	iv := in[:aes.BlockSize]
	offset := aes.BlockSize

	// start reading pubkey
	if !bytes.Equal(in[offset:offset+2], ciphCurveBytes[:]) {
		return nil, errUnsupportedCurve
	}
	offset += 2

	if !bytes.Equal(in[offset:offset+2], ciphCoordLength[:]) {
		return nil, errInvalidXLength
	}
	offset += 2

	xBytes := in[offset : offset+32]
	offset += 32

	if !bytes.Equal(in[offset:offset+2], ciphCoordLength[:]) {
		return nil, errInvalidYLength
	}
	offset += 2

	yBytes := in[offset : offset+32]
	offset += 32

	pb := make([]byte, size)
	pb[0] = byte(0x04) // uncompressed
	copy(pb[1:33], xBytes)
	copy(pb[33:], yBytes)
	// 检查(X, Y)是否位于曲线上，如果位于曲线上，则创建一个Pubkey
	pubkey, err := ParsePubKey(pb, S256())
	if err != nil {
		return nil, err
	}

	// 检查密码文本的长度
	if (len(in)-aes.BlockSize-offset-sha256.Size)%aes.BlockSize != 0 {
		return nil, errInvalidPadding // not padded to 16 bytes
	}

	// read hmac
	messageMAC := in[len(in)-sha256.Size:]

	// 生成共享密钥
	ecdhKey := GenerateSharedSecret(priv, pubkey)
	derivedKey := sha512.Sum512(ecdhKey)
	keyE := derivedKey[:32]
	keyM := derivedKey[32:]

	// verify mac
	hm := hmac.New(sha256.New, keyM)
	hm.Write(in[:len(in)-sha256.Size]) // everything is hashed
	expectedMAC := hm.Sum(nil)
	if !hmac.Equal(messageMAC, expectedMAC) {
		return nil, errInvalidMAC
	}

	// 开始解密
	block, err := aes.NewCipher(keyE)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	// 长度与密文相同
	plaintext := make([]byte, len(in)-offset-sha256.Size)
	mode.CryptBlocks(plaintext, in[offset:len(in)-sha256.Size])

	//return removePKCSPadding(plaintext)			//原来方法,返回removePKCSPadding(明文)
	length := len(plaintext)
	padLength := int(plaintext[length-1])
	if padLength > aes.BlockSize || length < aes.BlockSize {
		return nil, errInvalidPadding
	}

	return plaintext[:length-padLength], nil
}

// GenerateKeyPair 生成公私钥对,需要输入密码
func GenerateKeyPair(password string) (*PrivateKey, *PublicKey) {
	return PrivKeyFromBytes(S256(), []byte(password))
}

// GenerateKey 随机生成公私钥对
func GenerateKey() (*PrivateKey, *PublicKey) {
	i := time.Now().UnixNano()
	return PrivKeyFromBytes(S256(), conv.Int642bytes(i))
}

// FromECDSAPub 椭圆加密公钥转坐标
func FromECDSAPub(pub *PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(S256(), pub.X, pub.Y)
}

// FromECDSA 将私钥导出到二进制转储。
func FromECDSA(priv *PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

// toECDSA 使用给定的D值创建一个私钥。严格的参数控制键的长度是否应该在曲线大小上强制执行，或者它也可以接受遗留编码(0前缀)。
func toECDSA(d []byte, strict bool) (*PrivateKey, error) {
	priv := new(PrivateKey)
	priv.PublicKey.Curve = S256()
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

// HexToECDSA 解析secp256k1私钥。
func HexToECDSA(hexkey string) (*PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, errors.New("invalid hex string")
	}
	return ToECDSA(b)
}

// HexToECDSAPub 解析secp256k1公钥。
func HexToECDSAPub(hexkey string) (*PublicKey, error) {
	b, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, errors.New("invalid hex string")
	}
	return UnmarshalPubkey(b)
}

// ToECDSA 使用给定的D值创建一个私钥。
func ToECDSA(d []byte) (*PrivateKey, error) {
	return toECDSA(d, true)
}

// UnmarshalPubkey 将字节转换为secp256k1公钥。									待验证使用场景
func UnmarshalPubkey(pub []byte) (*PublicKey, error) {
	x, y := elliptic.Unmarshal(S256(), pub)
	if x == nil {
		return nil, errors.New("invalid secp256k1 public key")
	}
	return &PublicKey{Curve: S256(), X: x, Y: y}, nil
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// decompressPoint 在给定的X点和要使用的解的情况下，解压给定曲线上的一个点。
func decompressPoint(curve *KoblitzCurve, x *big.Int, ybit bool) (*big.Int, error) {
	// TODO: This will probably only work for secp256k1 due to
	// optimizations.

	// Y = +-sqrt(x^3 + B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)

	// //现在计算sqrt mod p (x2 + B)这个代码用于基于tonelli/shanks做一个完整的sqrt，但是它被https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294中引用的算法所替代
	y := new(big.Int).Exp(x3, curve.q, curve.Params().P)

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}
	return y, nil
}

// ParsePubKey 解析从字节串到ecdsa的koblitz曲线的公钥。公钥，验证它是否有效。它支持压缩、未压缩和混合签名格式。
func ParsePubKey(pubKeyStr []byte, curve *KoblitzCurve) (key *PublicKey, err error) {
	pubkey := PublicKey{}
	pubkey.Curve = curve

	if len(pubKeyStr) == 0 {
		return nil, errors.New("pubkey string is empty")
	}

	format := pubKeyStr[0]
	ybit := (format & 0x1) == 0x1
	format &= ^byte(0x1)

	switch len(pubKeyStr) {
	case PubKeyBytesLenUncompressed:
		if format != pubkeyUncompressed && format != pubkeyHybrid {
			return nil, fmt.Errorf("invalid magic in pubkey str: "+
				"%d", pubKeyStr[0])
		}

		pubkey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubkey.Y = new(big.Int).SetBytes(pubKeyStr[33:])
		// 混合键有额外的信息,利用它。
		if format == pubkeyHybrid && ybit != isOdd(pubkey.Y) {
			return nil, fmt.Errorf("ybit doesn't match oddness")
		}
	case PubKeyBytesLenCompressed:
		// format is 0x2 | solution, <X coordinate>
		// solution determines which solution of the curve we use.
		/// y^2 = x^3 + Curve.B
		if format != pubkeyCompressed {
			return nil, fmt.Errorf("invalid magic in compressed "+
				"pubkey string: %d", pubKeyStr[0])
		}
		pubkey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubkey.Y, err = decompressPoint(curve, pubkey.X, ybit)
		if err != nil {
			return nil, err
		}
	default: // wrong!
		return nil, fmt.Errorf("invalid pub key length %d",
			len(pubKeyStr))
	}

	if pubkey.X.Cmp(pubkey.Curve.Params().P) >= 0 {
		return nil, fmt.Errorf("pubkey X parameter is >= to P")
	}
	if pubkey.Y.Cmp(pubkey.Curve.Params().P) >= 0 {
		return nil, fmt.Errorf("pubkey Y parameter is >= to P")
	}
	if !pubkey.Curve.IsOnCurve(pubkey.X, pubkey.Y) {
		return nil, fmt.Errorf("pubkey isn't on secp256k1 curve")
	}
	return &pubkey, nil
}

// PublicKey 公钥是ecdsa。公钥与附加功能序列化在未压缩,压缩,和混合格式。
type PublicKey ecdsa.PublicKey

// ToECDSA 将公钥作为*ecdsa.PublicKey返回。
func (p *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return (*ecdsa.PublicKey)(p)
}

// Encrypt 主要目的是确保字节与Pyelliptic的兼容性。
func Encrypt(pubkey *PublicKey, in []byte) ([]byte, error) {
	//ephemeral, err := NewPrivateKey(S256())   暂省略
	key, err := ecdsa.GenerateKey(S256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ephemeral := (*PrivateKey)(key)
	derivedKey := sha512.Sum512(GenerateSharedSecret(ephemeral, pubkey)) //使用新生成的私钥和传入的公钥生成一个共享秘钥，Sum512返回数据的SHA512校验和。
	keyE := derivedKey[:32]
	keyM := derivedKey[32:]

	//paddedIn := addPKCSPadding(in)			原为方法，后去除
	padding := aes.BlockSize - len(in)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	paddedIn := append(in, padtext...)

	out := make([]byte, aes.BlockSize+70+len(paddedIn)+sha256.Size)
	iv := out[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	pb := ephemeral.PubKey().SerializeUncompressed()
	offset := aes.BlockSize
	copy(out[offset:offset+4], append(ciphCurveBytes[:], ciphCoordLength[:]...))
	offset += 4
	// X
	copy(out[offset:offset+32], pb[1:33])
	offset += 32
	// Y length
	copy(out[offset:offset+2], ciphCoordLength[:])
	offset += 2
	// Y
	copy(out[offset:offset+32], pb[33:])
	offset += 32

	// 开始加密
	block, err := aes.NewCipher(keyE) //根据传入的参数的长度，在AES-128, AES-192, or AES-256这三种加密方式中选择一种，然后返回对应的16, 24, 32位的新的密码块
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)                    //根据密码块的长度，生成加密模式
	mode.CryptBlocks(out[offset:len(out)-sha256.Size], paddedIn) //使用CryptBlocks对多个块进行加密或解密。src的长度必须是块大小的倍数。Dst和src可能指向相同的方向

	// start HMAC-SHA-256
	hm := hmac.New(sha256.New, keyM)
	hm.Write(out[:len(out)-sha256.Size])          // everything is hashed
	copy(out[len(out)-sha256.Size:], hm.Sum(nil)) // write checksum
	return out, nil
}

// SerializeUncompressed 将公钥序列化为65位的[]byte
func (p *PublicKey) SerializeUncompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenUncompressed)
	b = append(b, pubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

// SerializeCompressed 将公钥序列化为33位的[]byte
func (p *PublicKey) SerializeCompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubkeyCompressed
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, p.X.Bytes())
}

// SerializeHybrid 序列化一个65字节的混合格式的公钥.
func (p *PublicKey) SerializeHybrid() []byte {
	b := make([]byte, 0, PubKeyBytesLenHybrid)
	format := pubkeyHybrid
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

// PubkeyToAddress 公钥转地址方法
func (p *PublicKey) PubkeyToAddress() Address {
	pubBytes := FromECDSAPub(p)
	i := sha3.Keccak256(pubBytes[:])[12:]
	return BytesToAddress(i)
}

// CreateAddress 创建一个给定字节和nonce的ethereum地址
func CreateAddress(b Address, nonce uint64) Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return BytesToAddress(sha3.Keccak256(data)[12:])
}

// IsEqual 将此公钥实例与传递的公钥实例进行比较，如果两个公钥相等，则返回true。公钥等价于另一个公钥，如果它们具有相同的X和Y坐标。
func (p *PublicKey) IsEqual(otherPubKey *PublicKey) bool {
	return p.X.Cmp(otherPubKey.X) == 0 && p.Y.Cmp(otherPubKey.Y) == 0
}

// ToAddressMinHash returns the public key as ripemd160(sha256(sha256(key)))
func (pub *PublicKey) ToAddressMinHash() sha2.Ripemd160 {
	r1 := sha3.Sum256(pub.SerializeUncompressed())
	r2 := sha3.Sum256(r1[:])
	return sha2.HashRipemd160(r2[:])
}

// paddedAppend 将src字节片追加到dst，返回新的片。如果源的长度小于传递的大小，则在添加src之前先将前置零字节附加到dst片。
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// DoubleHashB 计算hash(hash(b))并返回结果字节。不管传入什么字符串，都将返回32位的固定字符串
func DoubleHashB(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}
