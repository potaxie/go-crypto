package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

//生成rsa的密钥对，并且保存到磁盘文件中
func GenerateRsaKey(keySize int) {

	//1。使用rsa肿的GenerateKey方法生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)

	if err != nil {
		panic(err)
	}

	//2.同多x509标准将得到的rsa私钥序列化为ASN.1的DER编码字符串

	derText := x509.MarshalPKCS1PrivateKey(privateKey)

	//3.要组成一个pem.Block

	block := pem.Block{
		Type:  "rsa private key",
		Bytes: derText,
	}

	//4.pem编码

	file, err := os.Create("private.pem")

	if err != nil {
		panic(err)
	}

	pem.Encode(file, &block)

	file.Close()

	//===================公钥==================

	//1。从私钥中取出公钥
	publicKey := privateKey.PublicKey
	//2。使用x509标准序列化
	derstream, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}

	//3。将得到的数据放到 pem block中

	block = pem.Block{
		Type:  "rsa public key",
		Bytes: derstream,
	}

	//4。pem编码
	file, err = os.Create("public.pem")

	if err != nil {
		panic(err)
	}

	pem.Encode(file, &block)

}

//RSA加密，公钥加密
func RSAEncrypt(plainText []byte, fileName string) []byte {
	//1。打开文件，读出内容
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}

	fileInfo, err := file.Stat()
	if err != nil {
		panic(err)
	}

	buf := make([]byte, fileInfo.Size())

	file.Read(buf)
	file.Close()
	//2.pem解码
	block, _ := pem.Decode(buf)
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	pubKey := pubInterface.(*rsa.PublicKey)

	//3.使用公钥加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)

	if err != nil {
		panic(err)
	}

	return cipherText
}

//RSA解密，私钥解密
func RSADecrypt(cipherText []byte, fileName string) []byte {
	//1。打开文件，读出内容
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}

	fileInfo, err := file.Stat()
	if err != nil {
		panic(err)
	}

	buf := make([]byte, fileInfo.Size())

	file.Read(buf)
	file.Close()

	//2.pem解码
	block, _ := pem.Decode(buf)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	//3.使用私钥解密
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)

	if err != nil {
		panic(err)
	}

	return plainText
}

func main() {
	GenerateRsaKey(1024)
	src := []byte("我是小谢，天天学习")
	cipherText := RSAEncrypt(src, "public.pem")
	plainText := RSADecrypt(cipherText, "private.pem")
	fmt.Println(string(plainText))

	myHash()
}

//使用sha256

func myHash() {

	//方式一：适用于少量数据的情况
	//sha256.Sum256([]byte("hello,go"))

	//方式二：适用于比较复杂的情况，例如1G的文件散列化，需要分开读
	//1.创建hash对象
	myHash := sha512.New()
	//2.添加数据
	src := []byte("我是小谢，天天学习,我是小谢，天天学习,我是小谢，天天学习")
	myHash.Write(src)
	myHash.Write(src)
	myHash.Write(src)
	//3.计算结果
	res := myHash.Sum(nil)
	//4.格式化为16进制的形式
	myStr := hex.EncodeToString(res)
	fmt.Printf("%s\n", myStr)

}
