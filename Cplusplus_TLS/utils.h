#include <string.h>
#include <ctype.h>
#include <string>
#include <regex>
#include <iostream>
#define LEN_TLS_HEADER 5

#define int_ntoa(x) inet_ntoa(*((struct in_addr *)&x))
using std::cout;
using std::endl;
using std::string;

// tls protocol头部
struct tls_header
{
    unsigned char content_type;  //tls数据包一个字节的content type
    //可能的取值包括change_cipher_spec(20), alert(21), handshake(22),application_data(23)等
    unsigned char version[2];  //tls版本信息的2个字节
    //可能的取值包括sslv3(0x300),tls1.0(0x301),gmtlsv1(0x101),tls1.1(0x302),tls1.2(0x303),tls1.3(0x304)等
    #define INET_TO_I(x) (((x)[0] << 8) + (x)[1]) //实现网络字节序到主机字节序的转换
    #define CLIENT_HELLO 1
    #define SERVER_HELLO 2
    #define FINISHED 20
    #define HANDSHAKE 22
    #define APPLICATION_DATA 23
    unsigned char len[2];//tls包除去头部的长度
};

//handshake protocol的头部
struct handshake_header
{
    unsigned char type;//握手消息类型
    //可能的取值包括
    unsigned char len[3];
    //握手数据包除去1字节类型和3字节长度，剩余部分的长度
    unsigned char version[2];//握手tls版本
    unsigned char random[32];//32字节的random int
    unsigned char session_id_len;//session id长度
    unsigned char session_id[32];//32字节的session id
};

//每个tls数据流特有的解密参数
struct security_param
{
    unsigned char master_secret[48];//master key
    unsigned char server_random[32];
    unsigned char client_random[32];
    unsigned char session_id[32];//是否必需?


    string str_master_secret;
    string str_server_random;
    string str_client_random;
    string str_session_id;
};

static inline int htoi(char *s);
int urldataDecode(char *str);
void print_hex_ascii_line(const unsigned char *payload, int len, int offset);
void print_payload(const unsigned char *payload, int len);
void print_url_str(string str, const char* label);
bool print_hit_mail_info(const string& plain_encoded);
void print_tom_mail_info(const string& plain_encoded);