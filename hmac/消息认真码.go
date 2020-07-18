package hmac

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
)

//生成消息认证码
func GenerateHmac(plainText, key []byte) []byte {

	//1.创建哈希接口，需要指定使用的哈希算法和密钥
	myhash := hmac.New(sha1.New, key)

	//2.给hash对象添加数据
	myhash.Write(plainText)

	//3.计算散列值
	hashText := myhash.Sum(nil)

	return hashText

}

//校验消息认证码
func VerifyHamc(plainText, key, hashText []byte) bool {
	//1.创建哈希接口，需要指定使用的哈希算法和密钥
	myhash := hmac.New(sha1.New, key)

	//2.给hash对象添加数据
	myhash.Write(plainText)

	//3.计算散列值
	hamc1 := myhash.Sum(nil)

	//4.两个散列值比较
	return hmac.Equal(hashText, hamc1)

}

func main() {

	src := []byte("测试接口测试")
	key := []byte("helloworld")
	hamc1 := GenerateHmac(src, key)
	b1 := VerifyHamc(src, key, hamc1)

	fmt.Printf("校验结果：%t\n", b1)
}
