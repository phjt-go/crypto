package ecdsa

import (
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/phjt-go/crypto/sha3"
	"github.com/phjt-go/util/conv"
	"math/big"
	"reflect"
	"strings"
)

// 地址长度是地址的期望长度
const AddressLength = 20

var addressT = reflect.TypeOf(Address{})

// Address 表示20字节地址
type Address [AddressLength]byte

// BytesToAddress byte转address
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

// StringToAddress 返回字节
func StringToAddress(s string) Address { return BytesToAddress([]byte(s)) }

// BigToAddress 返回字节值为b的地址。
func BigToAddress(b *big.Int) Address { return BytesToAddress(b.Bytes()) }

// HexToAddress 十六进制字符串转地址。
func HexToAddress(s string) Address { return BytesToAddress(conv.FromHex(s)) }

// IsHexAddress 验证字符串是否可以表示有效的十六进制编码的地址。
func IsHexAddress(s string) bool {
	if conv.HasHexPrefix(s) {
		s = s[2:]
	}
	return len(s) == 2*AddressLength && conv.IsHex(s)
}

// Bytes 字节获取底层地址的字符串表示形式。
func (a Address) Bytes() []byte { return a[:] }

// Big 将地址转换为一个大整数。
func (a Address) Big() *big.Int { return new(big.Int).SetBytes(a[:]) }

// Hash 哈希通过左填充0将地址转换为哈希。
func (a Address) Hash() Hash { return BytesToHash(a[:]) }

// Hex 十六进制返回地址的十六进制字符串表示形式。
func (a Address) Hex() string {
	unchecksummed := hex.EncodeToString(a[:])
	sha := sha3.NewKeccak256()
	sha.Write([]byte(unchecksummed))
	hash := sha.Sum(nil)

	result := []byte(unchecksummed)
	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}
	return "0x" + string(result)
}

// String 实现了fmt.Stringer字符串。
func (a Address) String() string {
	return strings.ToLower(a.Hex())
}

// Format 实现了fmt格式。格式化程序，强制按原样格式化字节片，而不需要通过用于日志记录的stringer接口。
func (a Address) Format(s fmt.State, c rune) {
	fmt.Fprintf(s, "%"+string(c), a[:])
}

// SetBytes 将地址设置为b的值。如果b大于len(a)，会宕机。
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// Scan 为数据库/sql实现了Scanner。
func (a *Address) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into Address", src)
	}
	if len(srcB) != AddressLength {
		return fmt.Errorf("can't scan []byte of len %d into Address, want %d", len(srcB), AddressLength)
	}
	copy(a[:], srcB)
	return nil
}

// Value 实现了数据库/sql的valuer。
func (a Address) Value() (driver.Value, error) {
	return a[:], nil
}

// UnprefixedAddress 允许封送一个没有0x前缀的地址。
type UnprefixedAddress Address

// MarshalText 将地址编码为十六进制。
func (a UnprefixedAddress) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(a[:])), nil
}

// MixedcaseAddress 保留了原始字符串，它可能被正确地校验和，也可能不被正确地校验和
type MixedcaseAddress struct {
	addr     Address
	original string
}

// MarshalJSON 封送原始值
func (ma *MixedcaseAddress) MarshalJSON() ([]byte, error) {
	if strings.HasPrefix(ma.original, "0x") || strings.HasPrefix(ma.original, "0X") {
		return json.Marshal(fmt.Sprintf("0x%s", ma.original[2:]))
	}
	return json.Marshal(fmt.Sprintf("0x%s", ma.original))
}

// Address 返回地址
func (ma *MixedcaseAddress) Address() Address {
	return ma.addr
}

// String 字符串实现fmt.Stringer
func (ma *MixedcaseAddress) String() string {
	if ma.ValidChecksum() {
		return fmt.Sprintf("%s [chksum ok]", ma.original)
	}
	return fmt.Sprintf("%s [chksum INVALID]", ma.original)
}

// ValidChecksum 如果地址具有有效校验和，则ValidChecksum返回true
func (ma *MixedcaseAddress) ValidChecksum() bool {
	return ma.original == ma.addr.Hex()
}

// Original 原始返回混合大小写输入字符串
func (ma *MixedcaseAddress) Original() string {
	return ma.original
}
