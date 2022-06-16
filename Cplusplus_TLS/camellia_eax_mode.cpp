/*
 * @Description: cryptopp usage reference
 * @Author: dive668
 * @Date: 2022-06-06 22:47:58
 * @LastEditTime: 2022-06-10 22:19:20
 */
//source code:https://gitee.com/locomotive_crypto/book_code/blob/master/chapter08_02/chapter08_02.cpp
#include<iostream> //使用cout、cin 
#include<camellia.h> //使用Camellia
#include<osrng.h> //使用AutoSeededRandomPool 
#include<secblock.h> //使用SecByteBlock
#include<filters.h> //使用StringSource、AuthenticatedEncryptionFilter、AuthenticatedDecryptionFilter
#include<hex.h> //使用HexEncoder
#include<files.h> //使用FileSink
#include<eax.h> //使用EAX
using namespace std; //std是C++的命名空间
using namespace CryptoPP; //CryptoPP是CryptoPP库的命名空间
int main()
{
	AutoSeededRandomPool rng; //定义随机数发生器对象，用于产生密钥和初始向量
	SecByteBlock key; //存储产生的密钥key
	string plain = "I like cryptography very much."; //待加的密明文字符串
	string cipher, recover; //定义两个string对象，分别存储加密后的密文和解密后的明文
	SecByteBlock iv; //存储初始向量
	try
	{//加密
		EAX< Camellia >::Encryption enc; //定义加密器对象
		key.resize(enc.DefaultKeyLength()); //申请一段空间，用于存放密钥
		rng.GenerateBlock(key, key.size()); //生成一个随机的密钥
		cout << "plain:"; //以十六进制打印输出待加密的明文
		StringSource sSrc(plain, true, new HexEncoder(new FileSink(cout)));
		iv.resize(enc.DefaultIVLength()); //为iv分配存储空间
		rng.GenerateBlock(iv, iv.size()); //产生初始向量iv
		enc.SetKeyWithIV(key, key.size(), iv, iv.size()); //设置密钥和初始向量
														  //加密字符串—利用enc加密字符串plain，并将加密结果存放于cipher中
		StringSource Enc(plain, true, new AuthenticatedEncryptionFilter(enc, new StringSink(cipher)));
		cout << endl << "cipher:"; //以十六进制打印输出加密的结果，即密文
		StringSource sCipher(cipher, true, new HexEncoder(new FileSink(cout)));
	}
	catch (const Exception& e)
	{//出现异常
		cout << e.what() << endl; //异常原因
		return 0;
	}
	try
	{//解密
		EAX< Camellia >::Decryption dec; //定义解密器对象
		dec.SetKeyWithIV(key, key.size(), iv, iv.size()); //设置密钥和初始向量
														  //解密字符串—利用dec解密字符串cipher，并将解密结果存放于recover中
		StringSource Dec(cipher, true, new AuthenticatedDecryptionFilter(dec, new StringSink(recover)));
		cout << endl << "recover:"; //以十六进制打印输出解密结果
		StringSource sRecover(recover, true, new HexEncoder(new FileSink(cout)));
		cout << endl;
	}
	catch (const Exception& e)
	{//出现异常
		cout << e.what() << endl; //异常原因
	}
	return 0;
}
