package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

func main() {

	//GenerateEccKey()
	src := []byte("使用X509对pem.Block中的Bytes变量中的数据进行解析->得到一个接口")

	rText, sText := EccSignature(src, "eccPrivate.pem")
	fmt.Printf("result1____", rText, sText, "\n")

	b1 := EccVerify(src, rText, sText, "eccPublic.pem")
	fmt.Printf("result2____", b1, "\n")

}

//1.生成密钥对

func GenerateEccKey() {
	//1.使用ecdsa生成密钥对,P224,P521
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	if err != nil {
		panic(err)
	}

	//2.将私钥写入磁盘
	//-使用x509进行序列化
	derText, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	//-将得到的切片字符串放入pem.Block结构体
	block := pem.Block{
		Type:  "ecdsa private key",
		Bytes: derText,
	}
	//-使用pem编码
	file, err := os.Create("eccPrivate.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(file, &block)
	file.Close()

	//3.将公钥写入磁盘
	//-从私钥中的得到公钥
	publicKey := privateKey.PublicKey
	//-使用x509进行序列化

	derText, err = x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	//-将得到的切片字符创放入pem.Block结构体中
	block = pem.Block{
		Type:  "ecdsa public key",
		Bytes: derText,
	}
	//-使用pembianma
	file, err = os.Create("eccPublic.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(file, &block)
	file.Close()
}

//ecc签名-私钥

func EccSignature(plainText []byte, privName string) (rText, sText []byte) {
	//打开磁盘的私钥文件
	file, err := os.Open(privName)
	if err != nil {
		panic(err)
	}
	//将私钥文件内容读出
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}

	buf := make([]byte, info.Size())
	file.Read(buf)
	file.Close()

	//2.使用pem数据进行解码
	block, _ := pem.Decode(buf)
	//3.使用x509,对私钥进行还原
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//4.对原始数据进行哈希运算--散列值
	hashText := sha1.Sum(plainText)

	//5.进行数字签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashText[:])
	if err != nil {
		panic(err)
	}
	//6.对r，s内存肿的数据进行格式化 ->[] byte
	rText, err = r.MarshalText()
	if err != nil {
		panic(nil)
	}

	sText, err = s.MarshalText()
	if err != nil {
		panic(nil)
	}

	return rText, sText
}

//ecc签名-认证

func EccVerify(plainText, rText, sText []byte, pubFile string) bool {

	//1.打开公钥文件，将里面的内容读出 -> []byte
	file, err := os.Open(pubFile)
	if err != nil {
		panic(err)
	}
	//将私钥文件内容读出
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}

	buf := make([]byte, info.Size())
	file.Read(buf)
	file.Close()
	//2.使用pem数据进行解码
	block, _ := pem.Decode(buf)
	//3.使用x509,对公钥还原
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	//4.将接口 -> 公钥
	publicKey := publicInterface.(*ecdsa.PublicKey)

	//5.对原始数据进行哈希运算 ->得到散列值
	hashText := sha1.Sum(plainText)

	//将rText,sText -> int 数据
	var r, s big.Int
	r.UnmarshalJSON(rText)
	s.UnmarshalJSON(sText)

	//6.签名的认证 -> ecdsa

	b1 := ecdsa.Verify(publicKey, hashText[:], &r, &s)

	return b1
}
