package des

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

//des的cbc加密

//编写填充函数，如果最后一个分组字节数不够，填充

//字节数刚好合适，添加一个新的分组

//填充的字节的值 == 缺少了的字节的数

//cbc填充分组的code
func paddingLastGroup(plainText []byte, blockSize int) []byte {

	//1.求出最后一个组中剩的字节数
	padNum := blockSize - len(plainText)%blockSize

	//2.创建新的切片，长度等于padNum，每个字节值 bytePadNum
	char := []byte{byte(padNum)}

	//切片创建，并初始化
	newPlain := bytes.Repeat(char, padNum)

	//3.newPlane数组追加到原始明文的后面
	newText := append(plainText, newPlain...)

	return newText
}

//去掉填充的数据
func unPaddingLastGroup(plainText []byte) []byte {

	//拿出切片里面最后一个字节
	length := len(plainText)
	lastChar := plainText[length-1]

	//尾部填充的字节个数
	number := int(lastChar)
	return plainText[:length-number]
}

//des加密使用cbc模式加密代码
func desEncrypt(plainText, key []byte) []byte {
	//1.建立一个底层使用的des密码接口

	block, err := des.NewCipher(key)

	if err != nil {
		panic(err)
	}

	fmt.Printf("cccc")
	//2.明文填充
	newText := paddingLastGroup(plainText, block.BlockSize())

	//3.创建一个使用cbc分组接口
	iv := []byte("12345678")

	blockMode := cipher.NewCBCEncrypter(block, iv)

	//4.加密
	cipherText := make([]byte, len(newText))

	blockMode.CryptBlocks(cipherText, newText)

	return cipherText

}

//des使用cbc模式解密代码
func desDecrypt(cipherText, key []byte) []byte {
	//1.创建一个底层使用des的密码接口
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}

	//2.创建一个使用cbc模式解密的接口
	iv := []byte("12345678")

	blockMode := cipher.NewCBCDecrypter(block, iv)

	//3.解密
	blockMode.CryptBlocks(cipherText, cipherText)

	//4.cipherText现在存储的是明文，需要删除加密时候填充的尾部数据
	plainText := unPaddingLastGroup(cipherText)
	return plainText
}

//aes加密使用ctc模式加密代码
func aesEncrypt(plainText, key []byte) []byte {
	//1.建立一个底层使用的aes密码接口

	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	//3.创建一个使用ctr分组接口
	//go接口中的iv可以理解为随机数种子，iv的长度 == 明文分组的长度
	iv := []byte("12345678abcdefgh")
	stream := cipher.NewCTR(block, iv)

	//4.加密
	cipherText := make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)

	return cipherText
}

//aes加密使用ctc模式解密代码，其实跟加密一样
func aesDecrypt(cipherText, key []byte) []byte {
	//1.建立一个底层使用的aes密码接口

	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	//3.创建一个使用ctr模式解密接口
	//go接口中的iv可以理解为随机数种子，iv的长度 == 明文分组的长度
	iv := []byte("12345678abcdefgh")
	stream := cipher.NewCTR(block, iv)

	//4.解密
	stream.XORKeyStream(cipherText, cipherText)
	return cipherText
}
