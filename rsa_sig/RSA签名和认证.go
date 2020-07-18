package rsa_sig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	src := []byte("测试接口测试onetwothree")

	sigText := SignatureRSA(src, "private.pem")

	b1 := VerifyRSA(src, sigText, "public.pem")
	fmt.Printf("校验结果：%t\n", b1)
}

//RSA签名 -- 私钥
func SignatureRSA(plainText []byte, fileName string) []byte {
	//打开磁盘的私钥文件
	file, err := os.Open(fileName)
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

	//使用pem对数据解码，得到pem.Block结构体变量
	block, _ := pem.Decode(buf)

	//x509将数据解析成私钥结构体->得到了私钥
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//创建一个哈希对象->md5/sha256
	myhash := sha512.New()

	//给hash对象添加数据
	myhash.Write(plainText)
	//计算hash值
	hashText := myhash.Sum(nil)
	//使用rsa肿的函数对散列值签名
	sigText, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashText)

	if err != nil {
		panic(err)
	}
	return sigText
}

//RSA签名认证
func VerifyRSA(plainText, sigText []byte, pubFileName string) bool {

	//打开公钥文件，将文件内容读取->[]byte
	file, err := os.Open(pubFileName)

	if err != nil {
		panic(err)
	}
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	file.Close()

	//使用pem解码 -> 得到pem.Block结果体变量
	block, _ := pem.Decode(buf)
	//使用x509对pem.Block中的Bytes变量中数据进行解析 -> 得到一接口
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//进行类型断言 -> 得到了公钥的结构体
	publicKey := pubInterface.(*rsa.PublicKey)
	//对原始数据进行hash运算（和签名使用的hash算法一致） -> 散列值
	hashText := sha512.Sum512(plainText)

	//签名认证 -rsa中的函数
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, hashText[:], sigText)
	if err == nil {
		return true
	}
	fmt.Printf("err______%s", err)
	return false
}
