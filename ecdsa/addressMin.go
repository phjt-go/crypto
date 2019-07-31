package ecdsa

import (
	"github.com/phjt-go/crypto/base58"
	"github.com/phjt-go/crypto/sha3"
	"strings"
)

// Checksum 4 bytes
type Checksum [4]byte

// AddressMin 为了更好的实现虚拟地址生成，AddressMin版本是一个25字节，一个20字节的公钥散列，1字节的地址类型和4字节的校验和。
type AddressMin struct {
	Version byte     //1 byte
	Key     [20]byte //20 byte pubkey hash
}

// AddressMinFromPubKey 根据公钥返回虚拟地址
func AddressMinFromPubKey(pubKey PublicKey) AddressMin {
	addr := AddressMin{
		Version: 0,
		Key:     pubKey.PubkeyToAddress(),
	}
	return addr
}

// Bytes 字节作为字节片返回地址
func (addr *AddressMin) Bytes() []byte {
	b := make([]byte, 20+1+4)
	copy(b[0:20], addr.Key[0:20])
	b[20] = addr.Version
	chksum := addr.Checksum()
	copy(b[21:25], chksum[0:4])
	return b
}

// Checksum 返回地址Checksum是sha256的前4个字节(key+version)
func (addr *AddressMin) Checksum() Checksum {
	// Version comes after the AddressMin to support vanity AddressMines
	r1 := append(addr.Key[:], []byte{addr.Version}...)
	r2 := sha3.Sum256(r1[:])
	c := Checksum{}
	copy(c[:], r2[:len(c)])
	return c
}

// String 返回一个字符串化的地址
func (addr AddressMin) String() string {
	return "0x" + strings.ToLower(base58.Encode(addr.Bytes(), base58.BscAlphabet))
}
