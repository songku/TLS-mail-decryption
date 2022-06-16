/*
 * @Description: hit mail tls decrypt
 * @Author: dive668
 * @Date: 2022-06-10 16:23:54
 * @LastEditTime: 2022-06-11 07:20:27
 */
#include <fstream>
#include <sstream>
#include "tls_decrypt.h"
#include "../cryptopp/cryptlib.h"
#include "../cryptopp/files.h"
#include "../cryptopp/hex.h"
#include "../cryptopp/sha.h"
#include "../cryptopp/hmac.h"
#include "../cryptopp/aes.h"
#include "../cryptopp/gcm.h"
#include "../cryptopp/filters.h"
#include <string>
#include <stddef.h>
#include <ctype.h>
#include <sys/types.h>
#include <nids.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
using namespace CryptoPP;
using namespace std;
using std::cout;
using std::endl;
using std::ifstream;
using std::string;
using std::stringstream;

char *pcap_file_path;
char *ssllog_path = "/home/centos7/Desktop/hit_mail_decrypt/tom_ssl.log"; //ssl key log file path

bool deal_tls(struct tcp_stream *a_tcp,struct security_param **s_ptr,bool is_from_server)
{
    char str_server_addr[64], str_client_addr[64];
    sprintf(str_server_addr, "%s:%i", int_ntoa(a_tcp->addr.saddr), a_tcp->addr.source);
    sprintf(str_client_addr, "%s:%i", int_ntoa(a_tcp->addr.daddr), a_tcp->addr.dest);
    const struct tls_header *tls; //tls header
    const struct handshake_header *hs;	//tls handshake header
    struct half_stream &half_s	//tcp流中的半流根据is_from_server来提取
    = is_from_server ? a_tcp->client :	a_tcp->server;
    char *packet = half_s.data;	//该半流中的数据部分
    int size_packet = half_s.count_new;	//新数据包的大小
    char *en_data = packet + LEN_TLS_HEADER; //当且仅当该数据包是tls appdata时，通过偏移量，读取该TLS Applicaiton Data部分
    struct security_param *s_param = *s_ptr; //安全参数
    unsigned long expected_data_len;	//处理数据包所必需的数据长度
    if (size_packet > 0) //包长度本身不符合规范，跳过
    {
        tls = (struct tls_header *)packet; //取tls头部
        expected_data_len = INET_TO_I(tls->len) + LEN_TLS_HEADER;
        switch (tls->content_type) //根据宏定义switch包类型
        {
        case HANDSHAKE: //握手包
            printf("%s -> %s len: %d\n", str_server_addr, str_client_addr, size_packet);
            hs = (struct handshake_header *)(packet + LEN_TLS_HEADER);
            {
                switch (hs->type)
                {
                case CLIENT_HELLO: // Client hello型TLS握手包
                {
                    if (!s_param->str_client_random.empty()) //判断安全参数中是否已经有client_random
                        goto encrypted_handshake;
                    cout<<"Client hello!"<<endl; //如果安全参数中没有client hello
                    memcpy(s_param->client_random, hs->random, 32);
                    memcpy(s_param->session_id, hs->session_id, (unsigned long)hs->session_id_len);
                    s_param->str_client_random.resize(64);
                    s_param->str_session_id.resize(64);
                    for (unsigned long i = 0; i < 32; i++)
                    {
                        sprintf((char *)s_param->str_client_random.c_str() + i * 2, "%02hhx", s_param->client_random[i]);
                        sprintf((char *)s_param->str_session_id.c_str() + i * 2, "%02hhx", s_param->session_id[i]);
                    }
                    //下面根据client random，到ssl.log中找匹配的master secret
                    ifstream fin(ssllog_path);
                    if (!fin)
                    {
                        cout << "ssllog file open failed!" << endl;
                        return true;
                    }
                    string tmp, line;
                    while (getline(fin, line))
                    {
                        // 注释以'#'开头，跳过ssl log中的这一行
                        if (line[0] == '#')
                            continue;
                        stringstream linestring(line); // 把该行作为一个字符串流，依据空格拆分读取
                        linestring >> tmp; //读取到第一个空格前的字段
                        if (tmp == "CLIENT_RANDOM")
                        {
                            linestring >> tmp; // client_random输出到tmp，还要进一步判断是否与当前流的client_random匹配
                            if (tmp == s_param->str_client_random)
                            {
                                // 匹配，则将linestring最后一部分输出到安全参数的master_secret
                                s_param->str_master_secret.resize(96);
                                linestring >> s_param->str_master_secret;
                                hexstr2bytes(s_param->str_master_secret, (unsigned char *)s_param->master_secret);
                                break;
                            }
                        }
                    }
                    fin.close();
                    break;
                }
                case SERVER_HELLO: //Server hello型TLS握手包
                {
                    if (!s_param->str_server_random.empty()) //判断安全参数中server_random是否为空
                        goto encrypted_handshake;
                    cout<<"Server hello!"<<endl;
                    memcpy(s_param->server_random, hs->random, 32);
                    s_param->str_server_random.resize(64);
                    for (unsigned long i = 0; i < 32; i++) //设置server_random
                        sprintf((char *)s_param->str_server_random.c_str() + i * 2, "%02hhx", s_param->server_random[i]);
                    break;
                }
                default: //其他类型的加密的握手包
                // TCP 报文长度是45 的话大概率是Finished 类型数据包，但是由于双方
                // change cipher spec 之后传输的数据便都为加密形式，因此需要一步解密
encrypted_handshake:
                    unsigned long len_en_data = INET_TO_I(tls->len);
                    string plain = decrypt_tls((unsigned char *)en_data, len_en_data,s_param, is_from_server);
                    hs = (handshake_header *)plain.c_str();
                    switch (hs->type)
                    {
                    case 20:
                        cout<<"Finished"<<endl;
                        break;
                    default:
                        cout<<"Error type: "<<hs->type<<endl;
                        break;
                    }
                }
            }
            cout<<endl;
            break;
        case APPLICATION_DATA: //如果tls数据包类型为appdata
        {
            if (expected_data_len > half_s.count - half_s.offset) //长度是否合规
                return false;
            unsigned long len_en_data = INET_TO_I(tls->len); //偏移到指向加密数据的位置
            string plain = decrypt_tls((unsigned char *)en_data, len_en_data,s_param, is_from_server); //尝试用安全参数解密加密数据包
            print_tom_mail_info(plain); //尝试打印出要查询的数据
        }
        break;
        default:
            break;
        }
    }
    // 如果数据足够的话我只需要丢弃已经处理过的数据，保留多余的数据留待下次处理
    nids_discard(a_tcp, expected_data_len);
    return true;
}

void tcp_callback(struct tcp_stream *a_tcp, struct security_param **s_ptr)
{
    char str_server_addr[64], str_client_addr[64];
    sprintf(str_server_addr, "%s:%i", int_ntoa(a_tcp->addr.saddr), a_tcp->addr.source);
    sprintf(str_client_addr, "%s:%i", int_ntoa(a_tcp->addr.daddr), a_tcp->addr.dest);
    
    if (a_tcp->nids_state == NIDS_JUST_EST)
    {
        struct security_param *s_param; //新创建一个security_param对象，跟踪该a_tcp流
        s_param = new struct security_param;
        *s_ptr = s_param;

        a_tcp->client.collect++; // 收集client端收到的数据
        a_tcp->server.collect++; // 收集server端收到的数据
        fprintf(stderr, "%s <-> %s established\n", str_server_addr, str_client_addr);
        return;
    }
    else if (a_tcp->nids_state == NIDS_CLOSE)
    {
        cout<<"new established tcp stream"<<endl;
        fprintf(stderr, "%s <-> %s closing\n", str_server_addr, str_client_addr);
        return;
    }
    else if (a_tcp->nids_state == NIDS_RESET)
    {
        fprintf(stderr, "%s <-> %s reset\n", str_server_addr, str_client_addr);
        return;
    }

    else if (a_tcp->nids_state == NIDS_DATA)
    {
        if (a_tcp->client.count_new)
        {
            if (!deal_tls(a_tcp, s_ptr, true)) // 处理client接收到的数据,is_from_server为true
                nids_discard(a_tcp, 0);
        }
        else
        {
            if (!deal_tls(a_tcp, s_ptr, false)) // 处理server接收到的数据,is_from_server为false
                nids_discard(a_tcp, 0);
        }
    }
}


int main(int argc,char* argv[])
{
    cout<<"usage:./tom_mail_decrypt <pcap_file_path> <ssllog_path> <outputfile_path>"<<endl;
    if(argc<4)
    {
        cout<<"parameter number not allowed"<<endl;
        exit(0);
    }
    char *pcap_file_path = argv[1] ; //pcap file path
    //char *ssllog_path = "/home/centos7/Desktop/hit_mail_decrypt/tom_ssl.log"; //ssl key log file path
    char *output_path = argv[3];
    FILE *stream;
    int i;
    for(i=1;i<4;++i)
    {
        cout<<argv[i]<<endl;
    }
    try
    {
        freopen("./out_info.txt", "w", stdout); //输出重定向，输出数据将保存在output_path文件中
    }
    catch(Exception e)
    {
        cout<<"set ouput file:"<<output_path<<"error"<<endl;
        exit(0);
    }
    nids_params.filename = pcap_file_path;
    struct nids_chksum_ctl temp;
    temp.action = 1;
    temp.netaddr = 0;
    temp.mask = 0;
    nids_register_chksum_ctl(&temp,1);
    if (!nids_init())
    {
        fprintf(stderr, "%s\n", nids_errbuf);
        exit(1);
    }
    nids_register_tcp((void *)tcp_callback);
    nids_run();
    return 0;
}