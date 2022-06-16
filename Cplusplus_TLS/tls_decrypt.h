#include "utils.h"
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <string>
#include <stddef.h>
#include <ctype.h>
#include <iostream>


#define LEN_TLS_HEADER 5  //TLS头部5字节，4个字节的
#define IMPLICIT_NONCE_LEN  4  //nonce长度
#define EXPLICIT_NONCE_LEN  8
#define TLS13_AEAD_NONCE_LENGTH	12
#define LEN_TCP_BEGIN 8  //TCP数据包初始8个字节
#define LEN_AUTH_TAG 16  //认证tag长度
#define LEN_MASTER_KEY 48  //master key长度
#define LEN_SEED 64  //seed长度
#define LEN_RANDOM_BYTES 32  //random长度
#define LEN_AAD 13  //AAD长度

using namespace CryptoPP;
using CryptoPP::AES;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using std::cout; //直接使用std命名空间,byte会和CryptoPP中的冲突
using std::endl;
using std::string;

void P_hash(const byte *secret, unsigned long len_secret,const byte *seed, unsigned long len_seed,byte *hash_out);
void PRF(const byte *secret, unsigned long len_secret,const byte *label, unsigned long len_label,const byte *seed, unsigned long len_seed,byte *hash_out);
void hexstr2bytes(string hexstr, unsigned char *bytes);
string decrypt_tls(
const byte *cipher_all, unsigned long len_cipher_all,
const byte *master_secret,
const byte *server_random, const byte *client_random,
bool is_from_server);
string decrypt_tls(const byte *cipher_all, unsigned long len_cipher_all,security_param *s_param, bool is_from_server);
