package ecdsa

import (
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"github.com/phjt-go/crypto/sha3"
	"github.com/phjt-go/util/conv"
	"math/big"
	"math/rand"
	"reflect"
)

// Hash 哈希表示任意数据的32字节Keccak256哈希。
type Hash [HashLength]byte

// 哈希长度是哈希的期望长度
const HashLength = 32

var hashT = reflect.TypeOf(Hash{})

// Bytes 获取基础散列的字节表示。
func (h Hash) Bytes() []byte { return h[:] }

// Big 将散列转换为大整数。
func (h Hash) Big() *big.Int { return new(big.Int).SetBytes(h[:]) }

// Hex 十六进制将散列转换为十六进制字符串。
func (h Hash) Hex() string { return conv.ToHex(h[:]) }

// TerminalString 实现日志。在日志记录期间格式化控制台输出的字符串。
func (h Hash) TerminalString() string {
	return fmt.Sprintf("%x…%x", h[:3], h[29:])
}

// String 实现了stringer接口，并且在对文件进行完整日志记录时也被日志记录器使用。
func (h Hash) String() string {
	return h.Hex()
}

// Format 实现了fmt格式。格式化程序，强制按原样格式化字节片，而不需要通过用于日志记录的stringer接口。
func (h Hash) Format(s fmt.State, c rune) {
	fmt.Fprintf(s, "%"+string(c), h[:])
}

// BytesToHash 将byte数组转换为hash
func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

// Keccak256Hash Keccak256转换为Hash类型
func Keccak256Hash(data ...[]byte) (h Hash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}

// BigToHash 将b的字节表示设置为hash。
func BigToHash(b *big.Int) Hash { return BytesToHash(b.Bytes()) }

// HexToHash 将十六进制的字符串表示为hash。
func HexToHash(s string) Hash { return BytesToHash(conv.FromHex(s)) }

// 反编组文本以十六进制语法解析散列。
/*func (h *Hash) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Hash", input, h[:])
}*/

// UnmarshalJSON以十六进制语法解析散列。
/*func (h *Hash) UnmarshalJSON(input []byte) error {
	return hexutil.UnmarshalFixedJSON(hashT, input, h[:])
}*/

// MarshalText返回h的十六进制表示。
/*func (h Hash) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}*/

// SetBytes 将哈希值设置为b
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

// Generate 实现测试接口。
func (h Hash) Generate(rand *rand.Rand, size int) reflect.Value {
	m := rand.Intn(len(h))
	for i := len(h) - 1; i > m; i-- {
		h[i] = byte(rand.Uint32())
	}
	return reflect.ValueOf(h)
}

// Scan sql实现了Scan接口。
func (h *Hash) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into Hash", src)
	}
	if len(srcB) != HashLength {
		return fmt.Errorf("can't scan []byte of len %d into Hash, want %d", len(srcB), HashLength)
	}
	copy(h[:], srcB)
	return nil
}

// Value 实现了valuer接口。
func (h Hash) Value() (driver.Value, error) {
	return h[:], nil
}

// UnprefixedHash 允许在没有0x前缀的情况下封送散列。
type UnprefixedHash Hash

// MarshalText 将散列编码为十六进制。
func (h UnprefixedHash) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(h[:])), nil
}
