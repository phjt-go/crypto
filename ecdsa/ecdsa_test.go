package ecdsa

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"bytes"
	"github.com/phjt-go/crypto/base58"
	"github.com/phjt-go/crypto/sha3"
	"log"
)

var prk *PrivateKey
var pub *PublicKey
var pri, _ = GenerateKey()
var testMessage = "abc7454480385556955618697817098332954057395722449793480218377692479888opq"

func init() {
	prk, pub = GenerateKeyPair("123456789")
	prkY, pubY = GenerateKeyPair("123456789")
}

func Test_GenerateKey(t *testing.T) {
	t.Log(pri)
	t.Log(pri.Y)
	t.Log(pri.D)
}

//s256(): 100000	     18930 ns/op  P256():100000	     15401 ns/op
func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey()
	}
}

/**
5000	    374997 ns/op	    8496 B/op	     147 allocs/op
*/
func BenchmarkSM2(t *testing.B) {
	t.ReportAllocs()
	for i := 0; i < t.N; i++ {
		priv, pub := GenerateKey() // 生成密钥对
		msg := []byte("test")
		sign, err := priv.Sign(msg) // 签名
		if err != nil {
			log.Fatal(err)
		}
		//	ok := priv.Verify(msg, priv.PubKey()) // 密钥验证
		ok := sign.Verify(msg, pub)
		if ok != true {
			fmt.Printf("Verify error\n")
		} else {
			fmt.Printf("Verify ok\n")
		}
	}
}

// 测试私钥转字符串，再从字符串转换回私钥
func Test_PrkConversion(t *testing.T) {

	fmt.Println(pri)
	k := hex.EncodeToString(FromECDSA(pri))
	fmt.Println(k)
	key, _ := HexToECDSA(k)
	fmt.Println(key)
}

// 测试公钥转字符串，再从字符串转换回公钥
func Test_PubConversion(t *testing.T) {
	privateKey, _ := GenerateKey()
	fmt.Println(privateKey.PublicKey)
	k := hex.EncodeToString(FromECDSAPub(privateKey.PubKey()))
	fmt.Println(k)
	key, _ := HexToECDSAPub(k)
	fmt.Println(key)
}

//测试根据地址和nonce值生成智能合约地址
func TestNewContractAddress(t *testing.T) {
	testAddrHex := pub.PubkeyToAddress().String()
	t.Log(testAddrHex)
	hexaddr := HexToAddress(testAddrHex)
	t.Log(hexaddr)
	contractAddr := CreateAddress(hexaddr, 1)
	t.Log(contractAddr.String())
}

//1000000	      2448 ns/op
func BenchmarkPubkeyToAddress(b *testing.B) {
	for i := 0; i < b.N; i++ {
		addr := pub.PubkeyToAddress()
		addr.String()
	}
}

//500000	      2928 ns/op
func BenchmarkAddressMinFromPubKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		key := AddressMinFromPubKey(*pub)
		key.String()
	}
}

//私钥返回对应的公钥
func Test_PubKey(t *testing.T) {
	t.Log(time.Now().UnixNano())
	pubKey := prk.PubKey() //私钥转公钥
	t.Log(pubKey)
	//address := pub.PubkeyToAddress()			公钥转地址

	testHash := sha3.NewKeccak256() //使用sha3的256进行hash
	testHash.Write([]byte(testMessage))
	h := testHash.Sum(nil)
	sign, _ := prk.Sign(h) //私钥签名
	t.Log(sign)
	t.Log(time.Now().UnixNano())

}

//5000000000	         0.39 ns/op GenerateKey生成方式
func BenchmarkPubKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pri.PubKey()
	}
}

//测性能
func TestPubKey(t *testing.T) {
	start := time.Now()
	fmt.Printf("开始%v \n", time.Now().UnixNano())
	abc := false
	for i := 1; i <= 5000000000; i++ {
		pri.PubKey()
		if i == 5000000000 {
			abc = true
		}
	}

	if abc == true {
		fmt.Printf("结束%v \n", time.Now().UnixNano())
		fmt.Printf("结束%v \n", time.Since(start))

		fmt.Println(abc)
	}

}

//2000000000	         0.41 ns/op GenerateKeyPair生成方式
func Benchmark_PubKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		prk.PubKey()
	}
}

/**
私钥加签(方法式)，返回值是[]byte - 压测    20000	     80213 ns/op
*/
func Benchmark_Sign(b *testing.B) {
	origin := []byte(testMessage)
	testHash := sha256.New()
	testHash.Write(origin)
	h := testHash.Sum(nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pri.Sign(h)
	}
}

//私钥加签(方法式)，返回值是[]byte - 压测   20000	    106365 ns/op  Tps:%v 1.882938s
func Test_Sign2(b *testing.T) {
	t0 := time.Now()
	for i := 0; i < 20000; i++ {
		testHash := sha256.New()
		testHash.Write([]byte(testMessage))
		h := testHash.Sum(nil)
		prk.Sign(h)
	}
	b.Log("创建成功,Tps:", time.Since(t0))
}

//生成公私钥对 - 测试方法
func Test_GenerateKeyPair(t *testing.T) {
	t.Log(prk)
	t.Log(pub)
}

//sha3 256加密内容
func Test_Keccak256(t *testing.T) {
	sha := sha3.Keccak256([]byte(testMessage))
	t.Log(sha)
}

// 椭圆加密公钥转坐标 - 待验证
func Test_FromECDSAPub(t *testing.T) {
	fmt.Println("公钥X值:", pub.X)
	fmt.Println("公钥Y值:", pub.Y)
	ecdsaPub := FromECDSAPub(pub)
	fmt.Println(ecdsaPub)
	x, y := elliptic.Unmarshal(S256(), ecdsaPub)
	fmt.Println("验证后X值:", x)
	fmt.Println("验证后Y值:", y)
}

// 椭圆加密验证 - 对x,y轴的值是否存在曲线上进行验证 - 测试方法
func Test_Decode(t *testing.T) {
	ecdsaPub := FromECDSAPub(pub)
	fmt.Println(ecdsaPub)
	x, y := elliptic.Unmarshal(S256(), ecdsaPub)
	t.Log(x, y)
}

// 公钥序列化，再将序列化后的公钥转换回来
func Test_UnmarshalPubkey(t *testing.T) {
	t.Log(pub)
	key, err := UnmarshalPubkey(pub.SerializeUncompressed())
	if err != nil {
		t.Error(err)
	}
	equal := key.IsEqual(pub)
	t.Log(equal)
}

//公钥加密，私钥解密
func Test_EncryptAndDecode(t *testing.T) {
	pubKey, err := ParsePubKey(pub.SerializeCompressed(), S256())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("加密前：", testMessage)

	// 公钥加密
	ciphertext, err := Encrypt(pubKey, []byte(testMessage))

	if err != nil {
		fmt.Println(err)
		return
	}
	// 私钥解密
	plaintext, err := Decrypt(prk, ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("解密后：", string(plaintext))
}

func Test_Encrypt(t *testing.T) {
	pubKey, _ := ParsePubKey(pub.SerializeCompressed(), S256())
	b, _ := Encrypt(pubKey, []byte("123456"))
	t.Log(b)
	t.Log(pubKey)
}

//10000	    187094 ns/op
func Benchmark_Encrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Encrypt(pri.PubKey(), []byte("123456"))
	}
}

//30000000	       102 ns/op
func BenchmarkDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Decrypt(pri, []byte("12341324564323215512311111111545123413245643232155123111111115456"))
	}
}

//私钥加签，公钥验签，使用DoubleHashB()生成hash。
func Test_SignAndVerify(t *testing.T) {
	pubKey, err := ParsePubKey(pub.SerializeCompressed(), S256()) //验证公钥是否有效
	if err != nil {
		t.Error(err)
		return
	}

	hash := DoubleHashB([]byte(testMessage))
	t.Log("Hash为：", hash)
	// 私钥签名
	sign, err := prk.Sign(hash)
	if err != nil {
		t.Error(err)
		return
	}
	// 解码十六进制编码的私钥
	fmt.Printf("Serialized Signature: %x\n", sign.Serialize())
	// 公钥验签。
	verified := sign.Verify(hash, pubKey)
	fmt.Printf("Serialized Verified? %v\n", verified)
}

//演示：生成公私钥 》 验证公钥 》 数据加密获得Hash 》 私钥签名;;接收者根据Hash和签名解出公钥 》 使用公钥验签 》 数据解密
func Test_Flow(t *testing.T) {
	// 	-----------------------------------------------------------------   数据初始化  -------------------------------------------------------------------------- //
	pubKey, err := ParsePubKey(pub.SerializeCompressed(), S256()) //验证公钥是否有效
	if err != nil {
		t.Log(err)
		return
	}
	// 	-----------------------------------------------------------------   发送方对数据进行处理  -----------------------------------------------------------------  //
	ciphered, err := Encrypt(pubKey, []byte(testMessage)) //使用公钥对信息进行加密
	fmt.Println("密文：", ciphered)
	if err != nil {
		t.Log(err)
		return
	}
	hash := DoubleHashB([]byte(ciphered)) //加密后的Hash

	fmt.Println("Hash：", hash)
	sign, err := prk.Sign(hash) //使用私钥对数据进行签名
	if err != nil {
		t.Log(err)
		return
	}

	fmt.Printf("Serialized Signature: %x\n", sign.Serialize()) // 解码十六进制编码的私钥
	// 	-----------------------------------------------------------------  接收方对数据进行解析 ---------------------------------------------------------------------	//
	if !sign.Verify(hash, pubKey) {
		fmt.Printf("签名验证失败")
		return
	}

	plaintext, err := Decrypt(prk, ciphered) // 解密数据
	if err != nil {
		t.Log(err)
		return
	}
	fmt.Println("原文为：", string(plaintext))

}

// 测试生成公私钥								100000	    22519 ns/op
func Benchmark_Create(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKeyPair("123456789")
	}
}
func Test_CreateAddress(t *testing.T) {
	prk, _ := GenerateKeyPair("123456789")
	s := hex.EncodeToString(prk.Serialize())
	t.Log(s)
}

// 加签和验签的压测							5000		376000 ns/op
func Benchmark_Verify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testHash := sha256.New()
		testHash.Write([]byte(testMessage))
		h := testHash.Sum(nil)
		sig, _ := prk.Sign(h)
		sig.Verify(h, pub)
	}
}

// 公钥转地址的压测							50000	     27386 ns/op
func Benchmark_PubToAddress(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, pub := GenerateKeyPair("123456789")
		address := pub.PubkeyToAddress()
		b.Log(address)
	}
}

//对序列化一个33字节的公钥进行压测 				20000000	  97.8 ns/op
func Benchmark_SerializeCompressed(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pub.SerializeCompressed()
	}
}

// 对序列化一个65字节混合格式的公钥进行压测 		10000000	  193 ns/op
func Benchmark_SerializeHybrid(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pub.SerializeHybrid()
	}
}

// 对序列化一个65字节的未压缩的公钥进行压测		10000000	  150 ns/op
func Benchmark_SerializeUncompressed(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pub.SerializeUncompressed()
	}
}

//加密和解密的完整示例
func TestExample_basic(t *testing.T) {
	_, publicKey := GenerateKeyPair("12345678")
	fmt.Println("公钥：", publicKey)
	//自定字母表
	myAlphabet := base58.BscAlphabet

	// 编码：
	input := []byte("0x1Aa2Bb3Cc4Dd5Ee6Ff7Gg8Hh9jJKkLlMmNnoPpQqrRSsTtUuVvWwXxYyZz") //要加密的数据
	encodedString := base58.Encode(input, myAlphabet)                               //加密数据必须为byte数组,使用指定的字母表进行加密
	//input2 :=[]byte("我是小黑")
	//encodedString2 := Encode(input2, myAlphabet)
	fmt.Printf("base58encode(%v) = %s\n", publicKey.SerializeUncompressed(), encodedString)
	fmt.Println(" - - - - - - - - - - - - - - - - - - - - - - 我是分隔符 - - - - - - - - - - - - - - - - - - - - - - ")

	// 解码
	decodedBytes, err := base58.Decode(encodedString, base58.BscAlphabet) //使用字母表对数据进行解密
	if err != nil {                                                       // 当encodedString包含字母以外的字符时发生错误
		fmt.Println("base58Decode error:", err)
	} else {
		fmt.Printf("base58decode(%s) = %v\n", encodedString, decodedBytes)
		if string(input) != string(decodedBytes) { //校验数据是否被篡改过
			fmt.Println("数据被篡改")
		} else {
			fmt.Println(string(decodedBytes)) //解密后的数据
		}
	}
	fmt.Println(" - - - - - - - - - - - - - - - - - - - - - - 我是结束分隔符 - - - - - - - - - - - - - - - - - - - - - - ")
}

//300000000	         4.62 ns/op
func BenchmarkS256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		S256()
	}
}

func TestSharedSecret(t *testing.T) {
	prv0, _ := GenerateKey() // = ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	pub0 := prv0.PubKey()
	prv1, _ := GenerateKey()
	pub1 := prv1.PubKey()

	ss0 := GenerateSharedSecret(prv0, pub1)

	ss1 := GenerateSharedSecret(prv1, pub0)

	t.Logf("Secret:\n%v %x\n%v %x", len(ss0), ss0, len(ss0), ss1)
	if !bytes.Equal(ss0, ss1) {
		t.Errorf("dont match :(")
	}
}
