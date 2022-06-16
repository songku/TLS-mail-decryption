/*
 * @Description: use 
 * @Author: dive668
 * @Date: 2022-06-09 16:17:40
 * @LastEditTime: 2022-06-13 11:23:50
 */
#include "tls_decrypt.h"

void P_hash(const byte *secret, unsigned long len_secret,const byte *seed, unsigned long len_seed,byte *hash_out)
{
    HMAC<SHA256> hmac(secret, len_secret);
    hmac.Update(seed, len_seed);
    unsigned char a[HMAC<SHA256>::DIGESTSIZE];
    hmac.Final(a);
    for (unsigned long i = 0; i < 2; i++)
    {
        unsigned char tmp[HMAC<SHA256>::DIGESTSIZE + len_seed];
        // tmp = a + seed
        memcpy(tmp, a, HMAC<SHA256>::DIGESTSIZE);
        memcpy(tmp + HMAC<SHA256>::DIGESTSIZE, seed, len_seed);
        hmac.Update(tmp, HMAC<SHA256>::DIGESTSIZE + len_seed);
        // hash_out += hmac(secret, a + seed)
        hmac.Final(hash_out + i * HMAC<SHA256>::DIGESTSIZE);
        // a = hmac(secret, a)
        hmac.Update(a, HMAC<SHA256>::DIGESTSIZE);
        hmac.Final(a);
    }
}

void PRF(const byte *secret, unsigned long len_secret,const byte *label, unsigned long len_label,const byte *seed, unsigned long len_seed,byte *hash_out)
{
    unsigned char tmp[len_seed + len_label];
    memcpy(tmp, label, len_label);
    memcpy(tmp + len_label, seed, len_seed);
    P_hash(secret, len_secret, tmp, len_seed + len_label, hash_out);
}


string decrypt_tls(const byte *cipher_all, unsigned long len_cipher_all,const byte *master_secret,const byte *server_random, const byte *client_random,bool is_from_server)
{
    unsigned char keyblock[128];
    unsigned char client_write_key[16];
    unsigned char server_write_key[16];
    unsigned char client_write_iv[4];
    unsigned char server_write_iv[4];

    if (len_cipher_all < LEN_TCP_BEGIN + LEN_AUTH_TAG)
    {
        fprintf(stderr, "Error TLS message\n");
        return "";
    }
    unsigned char seed[LEN_RANDOM_BYTES << 1]; //左移一位表示2进制左移一位，代表乘以2，预留一个client random和server random大小的空间
    memcpy(seed, server_random, LEN_RANDOM_BYTES);
    memcpy(seed + LEN_RANDOM_BYTES, client_random, LEN_RANDOM_BYTES);
    PRF(master_secret, LEN_MASTER_KEY, (const unsigned char *)"key expansion",13, seed, LEN_RANDOM_BYTES << 1, keyblock);
    unsigned long len_enc = len_cipher_all - LEN_TCP_BEGIN - LEN_AUTH_TAG; //加密数据长度
    string enc((const char *)cipher_all + LEN_TCP_BEGIN, len_enc); //指向加密数据开始处
    byte mac[LEN_AUTH_TAG]; //mac数据长度为LEN_AUTH_TAG
    memcpy(mac, cipher_all + LEN_TCP_BEGIN + len_enc, LEN_AUTH_TAG); //指向mac数据
    //从密钥材料中获取2个key和2个iv
    memcpy(client_write_key, keyblock, sizeof(client_write_key)); 
    memcpy(server_write_key, keyblock + sizeof(client_write_key), sizeof(server_write_key));
    memcpy(client_write_iv, keyblock + sizeof(server_write_key) + sizeof(client_write_key),sizeof(client_write_iv));
    memcpy(server_write_iv, keyblock + sizeof(server_write_key) + sizeof(client_write_key) + sizeof(client_write_iv),sizeof(server_write_iv));
    unsigned char salt[4];
    unsigned char explicit_nonce[LEN_TCP_BEGIN];
    unsigned char nonce[4 + LEN_TCP_BEGIN];
    if (is_from_server)
        memcpy(salt, server_write_iv, sizeof(server_write_iv));
    else
        memcpy(salt, client_write_iv, sizeof(client_write_iv));
    memcpy(explicit_nonce, cipher_all, LEN_TCP_BEGIN);
    memcpy(nonce, salt, sizeof(salt));
    memcpy(nonce + sizeof(salt), explicit_nonce, sizeof(explicit_nonce)); // nonce = salt + explicit nonce
    byte iv[ AES::BLOCKSIZE ];
    memcpy(iv, nonce, sizeof(nonce)); //iv的一部分:12字节的nonce
    iv[12] = 0x00;
    iv[13] = 0x00;
    iv[14] = 0x00;
    iv[15] = 0x02; // GCM mode。nonce应该加上00000001才是真正的完整的iv。如果是CTR mode，则应该加上00000002
    CTR_Mode<AES>::Decryption dec;
    if (is_from_server)
        dec.SetKeyWithIV(server_write_key, sizeof(server_write_key), iv, sizeof(iv));
    else
        dec.SetKeyWithIV(client_write_key, sizeof(client_write_key), iv, sizeof(iv));
    std::string plain;
    try
    {
        StringSource Dec(enc, true, //因为是ctr模式，仅仅用到了enc(加密的数据部分)，不包括mac认证部分
        new StreamTransformationFilter(dec,new StringSink(plain))); //StreamTransformationFilter
        return plain;
    }
    catch (CryptoPP::Exception &e)
    {
        std::cerr << e.what() << endl;
        exit(1);
    }
}

string decrypt_tls(const byte *cipher_all, unsigned long len_cipher_all,security_param *s_param, bool is_from_server)
{
    return decrypt_tls(cipher_all, len_cipher_all,
    s_param->master_secret,
    s_param->server_random,
    s_param->client_random,
    is_from_server);
}