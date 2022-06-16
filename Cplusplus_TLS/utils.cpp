/*
 * @Description: 一些结构的定义及打印数据需要的一些函数
 * @Author: dive668
 * @Date: 2022-06-09 22:10:50
 * @LastEditTime: 2022-06-11 13:11:46
 */

#include "utils.h"


void hexstr2bytes(string hexstr, unsigned char *bytes)
{
    //实现思想：两个str转为unsigned long,再强制转为byte,放入byte数组
    //string头文件的c_str()函数把string对象转换成c中的字符串,返回一个指向正规C字符串的指针常量
    char tmpchr[5];
    unsigned char tmp = 0;//存储转换后的unsigned long
    int length = hexstr.size();
    const char *instr = hexstr.c_str();
    for(unsigned long i = 0; i < length; i += 2)
    {
        memset(tmpchr, 0, 5);
        memcpy(tmpchr, hexstr.c_str() + i, 2);
        tmp = strtoul(tmpchr, NULL, 16);
        bytes[i/2] =tmp; //i是2的偶数倍
    }
}

static inline int htoi(char *s)//将s指向的两个16进制字符转为对应的int值
{
    int value;
    int c;
    c = ((unsigned char *)s)[0];
    if (isupper(c)) //判断大写字符，转小写
        c = tolower(c);
    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;
    c = ((unsigned char *)s)[1];
    if (isupper(c))
        c = tolower(c);
    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;
    return (value);
}

string urldataDecode(string encoded_urldata){
    string decoded_url;
    char ch;
    int i=0,ch_addr=0, len = encoded_urldata.length();
    for (i=0; i < len; i++){
        if(encoded_urldata[i] != '%'){//不是url编码后的%字符
            if(encoded_urldata[i] == '+')
                decoded_url += ' ';//url中为+符号，则转为一个空格
            else //否则追加在后面
                decoded_url += encoded_urldata[i];
        }else{ //是url编码后的%字符，则从%后取两个url编码值，转为一个字符并追加
            sscanf(encoded_urldata.substr(i + 1, 2).c_str(), "%x", &ch_addr);
            ch = static_cast<char>(ch_addr);//将此地址处的字符转化出来，追加到末尾
            decoded_url += ch;
            i = i + 2;
        }
    }
    //std::cout<<"decoded url:"<<decoded_url<<std::endl;
    return decoded_url;
}

bool print_hit_mail_info(const string& plain_encoded) //参数plain_encoded是引用
{
    std::smatch matchLogin;
    std::smatch matchSendMail;
    string plain=urldataDecode(plain_encoded);
    std::regex_search(plain, matchLogin, std::regex(".*&uid=(.*?)&domain=(.*?)&password=(.*?)&.*"));
    //遇到含有双引号的正则匹配，注意加\转义
    std::regex_search(plain, matchSendMail, std::regex("\"account\":\"(.*?)\",\"to\":(.*?),.*\"subject\":\"(.*?)\",.*\"content\":\"(.*?)\",.*"));
    if(!matchLogin.empty())
    {
        cout<<"username:"<<matchLogin[1]<<endl;
        cout<<"password:"<<matchLogin[2]<<endl;
        return true;
    }
    else if (!matchSendMail.empty())
    {
        cout<<"from:"<<matchSendMail[1]<<endl;
        cout<<"to:"<<matchSendMail[2]<<endl;
        cout<<"subject:"<<matchSendMail[3]<<endl;
        cout<<"content:"<<matchSendMail[4]<<endl;
        return true;
    }
    else
        return false;
}


void print_tom_mail_info(const string& plain_encoded)
{
    string plain=urldataDecode(plain_encoded);
    string::size_type pos=0;
    if(plain.find("POST",pos)!=string::npos)
    {
        //找到post，进而在post数据中查询
        cout<<"find post data,start searching sensitive info in post data...."<<endl;
        if(plain.find("username=",pos)!=string::npos)
        {
            string::size_type pos1=0,pos2=0;
            cout<<"matched login info!"<<endl;
            pos1=plain.find("username=",pos);
            pos2=plain.find("&",pos1);//从找到username的位置开始，找到一个换行符，表示结束,可能没有换行符，从pos开始输出即可
            string username=plain.substr(pos1,pos2-pos1);
            string password=plain.substr(pos2+1); //从pos2+1到末尾
            cout<<"username:"<<username<<endl;
            cout<<"password:"<<password<<endl;
        }
        else
        {
            cout<<"no sensitive info in this post data...."<<endl;
            return;
        }
    }
    else if(plain.find("from=",pos)!=string::npos)
    {
        //from=songku@tom.com&to=lkrwz@sina.com&cc=&bcc=&&bFileDatas=&fh=&toa=&cca=&bcca=&subject=https ä¸ťé˘&uid=&uuid=&draftuid=&inboxid=&folderName=&status=write&defaultSignature=&text=<p>httpsĺĺŽš</p>
        string::size_type pos1=0,pos2=0,pos3=0,pos4=0,pos5=0,pos6=0,pos7=0;
        cout<<"matched send mail info!"<<endl;
        pos1=plain.find("from=",pos); //pos1指向from开始
        pos2=plain.find("&to=",pos1); //pos2指向to开始
        string from=plain.substr(pos1+5,pos2-pos1-5); //从from=后面开始取子串
        pos3=plain.find("&cc",pos2); //pos3指向cc
        string to=plain.substr(pos2+4,pos3-pos2-4); //直接取&to=后面
        pos4=plain.find("&subject",pos3)+1; //pos4指向subject
        pos5=plain.find("&uid",pos4);
        string subject=plain.substr(pos4+8,pos5-pos4-8); //直接取subject=后面
        pos6=plain.find("text",pos5); //pos6指向text
        pos7=plain.find("&save",pos6);  
        string text=plain.substr(pos6+5,pos7-pos6-6);  //直接取text=后面
        cout<<"from:"<<from<<endl;
        cout<<"to:"<<to<<endl;
        cout<<"subject:"<<subject<<endl;
        cout<<"content:"<<text<<endl;
    }
    else        
        return;
}


void print_hex_ascii_line(const unsigned char *payload, int len, int offset)
//该函数是为了将payload指向的内容更加可视化地展示在stdout上
{
    int i;
    int gap;
    const unsigned char *ch;
    printf("%05d	", offset); //打印一下offset
    ch = payload; //先打印hex十六进制编码值
    for (i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
        if (i == 7) //如果打印了8个字节，则再打印一个空格以和后面部分分隔
            printf(" ");
    }
    if (len < 8) //如果len小于8个字节，则打印一个空格
        printf(" ");
    if (len < 16) //以16个字节为基准，以空格填充不够16字节的部分
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            printf("	");
        }
    }
    printf("	");
    ch = payload;  //如果isprint()，即如果是可以ascii编码的，则将其打印出来(ascii完整范围0x00-0xff)
    for (i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");
    return;
}

void print_payload(const unsigned char *payload, int len)
//打印payload指向的数据包的内容，是对print_hex_ascii_line的循环调用
{

    int len_cnt = len;  //记录未打印出来的长度,len_cnt=0则打印结束
    int line_width = 16; //打印信息每行的字节数设置为16字节
    int line_len; //记录每一行的打印长度
    int offset = 0; //从0开始的偏移量计数值
    const unsigned char *ch = payload;
    if (len <= 0) //长度<=0，直接返回
        return;
    if (len <= line_width) //长度不超过一行，打印一行后返回
    {
        print_hex_ascii_line(ch, len, offset);
        return;
    }
    while (1) //不满足上述情况，则长度至少是多个16字节行
    {
        line_len = line_width % len_cnt;
        print_hex_ascii_line(ch, line_len, offset);
        len_cnt = len_cnt - line_len;
        ch = ch + line_len; //字符指针移动
        offset = offset + line_width;
        if (len_cnt <= line_width)
        {
            print_hex_ascii_line(ch, len_cnt, offset);
            break;
        }
    }
    return;
}