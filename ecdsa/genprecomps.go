// 此文件在常规构建过程中由于以下构建标记而被忽略。它由go generate调用，用于自动生成用于加速操作的预计算表。
// +build ignore

package ecdsa

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func main() {
	fi, err := os.Create("secp256k1.go")
	if err != nil {
		log.Fatal(err)
	}
	defer fi.Close()

	// 压缩序列化的字节点。
	serialized := S256().SerializedBytePoints()
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	if _, err := w.Write(serialized); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	w.Close()

	// 用base64对压缩的字节点进行编码。
	encoded := make([]byte, base64.StdEncoding.EncodedLen(compressed.Len()))
	base64.StdEncoding.Encode(encoded, compressed.Bytes())

	fmt.Fprintln(fi, "// Copyright (c) 2015 The btcsuite developers")
	fmt.Fprintln(fi, "// Use of this source code is governed by an ISC")
	fmt.Fprintln(fi, "// license that can be found in the LICENSE file.")
	fmt.Fprintln(fi)
	fmt.Fprintln(fi, "package btcec")
	fmt.Fprintln(fi)
	fmt.Fprintln(fi, "// Auto-generated file (see genprecomps.go)")
	fmt.Fprintln(fi, "// DO NOT EDIT")
	fmt.Fprintln(fi)
	fmt.Fprintf(fi, "var secp256k1BytePoints = %q\n", string(encoded))

	a1, b1, a2, b2 := S256().EndomorphismVectors()
	fmt.Println("The following values are the computed linearly independent vectors needed to make use of the secp256k1 endomorphism:")
	fmt.Printf("a1: %x\n", a1)
	fmt.Printf("b1: %x\n", b1)
	fmt.Printf("a2: %x\n", a2)
	fmt.Printf("b2: %x\n", b2)
}
