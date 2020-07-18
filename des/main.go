package des

import "fmt"

func main() {
	fmt.Printf("des 加解密")

	key := []byte("1234abdd")

	src := []byte("特点：密文没有规律，明文分组是一个数据流进行的按位异或操作，最终生成了密文")

	cipherText := desEncrypt(src, key)
	plainText := desDecrypt(cipherText, key)

	fmt.Printf("解密之后的数据%s\n", string(plainText))

	fmt.Printf("aes加解密ctr模式...")
	key1 := []byte("1234abdd12345678")
	cipherText = aesEncrypt(src, key1)
	plainText = aesDecrypt(cipherText, key1)

	fmt.Printf("解密之后的数据%s\n", string(plainText))

}
