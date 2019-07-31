package ecdsa

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

//验证通过私钥和椭圆曲线，hash等生成压缩签名，再验签后返回公钥的过程
func Test_SignCompact(t *testing.T) {
	// 	----------   数据初始化  ---------- //
	pubKey, err := ParsePubKey(pub.SerializeCompressed(), S256()) //验证公钥是否有效
	fmt.Println("公钥:", pubKey)
	if err != nil {
		t.Log(err)
		return
	}

	// 	----------   发送方对数据进行处理  ----------  //
	ciphered, err := Encrypt(pubKey, []byte(testMessage)) //使用公钥对信息进行加密
	fmt.Println("加密后：", ciphered)
	if err != nil {
		t.Log(err)
		return
	}

	testHash := sha256.New()
	testHash.Write([]byte(ciphered))
	hash := testHash.Sum(nil)
	sign, err := SignCompact(S256(), prk, hash, true) //私钥加签
	if err != nil {
		t.Log(err)
		return
	}

	fmt.Printf("序列化后的签名: %x\n", sign)
	fmt.Println("签名长度位数为：", len(sign))

	if err != nil {
		t.Log(err)
		return
	}
	// 	----------  接收方对数据进行解析 ----------	//
	pubb, _, err := RecoverCompact(S256(), sign, hash) //公钥验签
	t.Log("还原后的公钥", pubb)
	equal := pubb.IsEqual(pubKey)
	t.Log("对比结果为", equal)

	plaintext, err := Decrypt(prk, ciphered) // 解密数据
	if err != nil {
		t.Log(err)
		return
	}
	fmt.Println("原文为：", string(plaintext))
}

var prkY *PrivateKey
var pubY *PublicKey

//验证通过私钥和椭圆曲线，hash等生成压缩签名，再验签后返回公钥的过程
func Test_SignCompact2(t *testing.T) {
	// 	---------- 发送方  数据初始化  ---------- //
	pubKey, err := ParsePubKey(pub.SerializeCompressed(), S256()) //验证公钥是否有效
	fmt.Println("公钥:", pubKey)
	if err != nil {
		t.Log(err)
		return
	}

	// 	----------   发送方对数据进行处理  ----------  //
	ciphered, err := Encrypt(pubKey, []byte(testMessage)) //使用公钥对信息进行加密
	fmt.Println("加密后：", ciphered)
	if err != nil {
		t.Log(err)
		return
	}

	testHash := sha256.New()
	testHash.Write([]byte(ciphered))
	hash := testHash.Sum(nil)
	sign, err := SignCompact(S256(), prkY, hash, true) //私钥加签
	if err != nil {
		t.Log(err)
		return
	}

	fmt.Printf("序列化后的签名: %x\n", sign)
	fmt.Println("签名长度位数为：", len(sign))

	if err != nil {
		t.Log(err)
		return
	}
	// 	----------  接收方对数据进行解析 ----------	//

	pubb, _, err := RecoverCompact(S256(), sign, hash)         //公钥验签
	pp, err := ParsePubKey(pubb.SerializeCompressed(), S256()) //验证公钥是否有效
	if err != nil {
		fmt.Println("err：", err)
	} else {
		fmt.Println("pp：", pp)
	}
	t.Log("还原后的公钥", pubb)
	equal := pubb.IsEqual(pubY)
	t.Log("对比结果为", equal)
	plaintext, err := Decrypt(prk, ciphered) // 解密数据
	if err != nil {
		t.Log(err)
		return
	}
	fmt.Println("原文为：", string(plaintext))
}
func getAddress() string {
	return "矿工地址"
}

//验证通过私钥和椭圆曲线，hash等生成压缩签名，再验签后返回公钥的过程
func Test_SignCompact3(t *testing.T) {
	// 	---------- 管理员发送方  数据初始化  ---------- //
	address := getAddress() //矿工地址
	hash := sha256.Sum256([]byte(address))
	sign, err := SignCompact(S256(), prkY, hash[:], true) //私钥加签
	if err != nil {
		t.Log(err)
		return
	}

	fmt.Printf("序列化后的签名: %x\n", sign)
	fmt.Println("签名长度位数为：", len(sign))

	if err != nil {
		t.Log(err)
		return
	}

	// 	----------  接收方对数据进行解析 ----------	//
	pubb, _, err := RecoverCompact(S256(), sign, hash[:]) //公钥验签
	isEqual := pubb.IsEqual(pubY)
	if !isEqual {
		fmt.Println("错误")
	}
	pp, err := ParsePubKey(pubb.SerializeCompressed(), S256()) //验证公钥是否有效
	if err != nil {
		fmt.Println("err：", err)
	} else {
		fmt.Println("pp：", pp)
	}
	address2 := getAddress() //矿工地址
	hash2 := sha256.Sum256([]byte(address2))
	t.Log("还原后的Hash", hash)
	t.Log("我的Hash", hash2)

}

// TestPrvKeySign 签名测试
func TestPrvKeySign(t *testing.T) {

	// 节点地址
	address := "0x89d336c09c1a8777201970e4fb4b1676f8f750ac"

	// 管理员私钥字符串
	mPrivateKey := "89d2b7fc2bd60ebf29c3b1da24eb74cd6911019c3f1e072c6c4dcec466d7f6bc"

	// 推导地址hash
	hash := DoubleHashB([]byte(address))

	// 管理员私钥签名
	signature, err := PrvKeySign(mPrivateKey, hash)
	if err != nil {
		t.Errorf("签名失败：%v", err)
	}
	t.Log("私钥签名：", hex.EncodeToString(signature))
}

// TestPubKeyCheckSign 验签测试
func TestPubKeyCheckSign(t *testing.T) {
	// 节点地址
	address := "0x528da20666570354a1348a8825633aefc915f7ba"

	// 管理员私钥字符串
	mPrivateKey := "89d2b7fc2bd60ebf29c3b1da24eb74cd6911019c3f1e072c6c4dcec466d7f6bc"

	// 管理员公钥字符串
	mPublicKey := "040849fa80cdc6ac365f1506989f704b7f0a55ea8bc106fb9a8e2327293a556e2d4e8d1e902c8dfec0d73a6838a62000b2f26f510967d6e0b63bf63e3416e420b1"

	// 推导节点地址hash
	hash := DoubleHashB([]byte(address))

	// 管理员私钥签名
	signature, err := PrvKeySign(mPrivateKey, hash)
	if err != nil {
		t.Errorf("签名失败：%v", err)
	}

	// 签名校验
	checked, err := PubKeyCheckSign(signature, hash, mPublicKey)
	if err != nil {
		t.Error(err)
	}
	t.Log(checked)
}

// BenchmarkPrvKeySign 签名压测
func BenchmarkPrvKeySign(b *testing.B) {
	// 节点地址
	address := "0x89d336c09c1a8777201970e4fb4b1676f8f750ac"

	// 管理员私钥字符串
	mPrivateKey := "89d2b7fc2bd60ebf29c3b1da24eb74cd6911019c3f1e072c6c4dcec466d7f6bc"

	// 推导地址hash
	hash := DoubleHashB([]byte(address))

	for i := 0; i < b.N; i++ {
		// 管理员私钥签名
		PrvKeySign(mPrivateKey, hash)
	}
}

// BenchmarkPubKeyCheckSign 验签压测
func BenchmarkPubKeyCheckSign(b *testing.B) {

	// 管理员公钥字符串
	mPublicKey := "040849fa80cdc6ac365f1506989f704b7f0a55ea8bc106fb9a8e2327293a556e2d4e8d1e902c8dfec0d73a6838a62000b2f26f510967d6e0b63bf63e3416e420b1"

	sign := "20a4272a16faa252bbbbc85ba07d6c908d3a4fc0da75572a010bee763a6b4c5b0e3284a89b522d8e702971c54d607037ccbbb09df5dd610ebd98eeb94d4d6b8ef0"

	// 节点地址
	address := "0x89d336c09c1a8777201970e4fb4b1676f8f750ac"

	// 推导地址hash
	hash := DoubleHashB([]byte(address))

	// 签名校验
	signature, _ := hex.DecodeString(sign)

	for i := 0; i < b.N; i++ {
		PubKeyCheckSign(signature, hash, mPublicKey)
	}
}
