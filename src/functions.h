#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#pragma comment(lib,"ws2_32.lib")

/**IP address of external DNS server*/
#define EXTERNAL_DNS "10.3.9.4"
/**default open path of IP_Domain table*/
#define DEFAULT_PATH "dnsrelay.txt"
/**max length of IP address*/
const int IP_LENGTH=16;
/**max length of open path*/
const int PATH_LENGTH=50;
/**max length of domain address*/
const int DOMAIN_LENGTH=256;
/**upper limit of entities of IP_Domain table*/
const int ENTITIES=300;
/**port number of server*/
const unsigned short PORT=53;
/**max size of message buffer*/
const int BUF_SIZE=512;
/**set timeout 0.5s*/
const int TIMEOUT=500;
/**offset value of new id*/
const unsigned short OFFSET=4096;

/**DNS message header structure*/
class Header
{
public:
    unsigned short id; //(2 bytes) 标识
    unsigned short flags; //(2 bytes) 标志
    /*QR(1 bit)     0查询 1响应
     *OPCODE(4 bit) 0标准查询
     *AA(1 bit)     权威答案 通常为0
     *TC(1 bit)     1表示长度大于512字节 被截断
     *RD(1 bit)     期望递归 通常为1 查询报中设置响应报中返回
     *RA(1 bit)     递归可用 在响应报文中通常为1
     *Z(3 bit)      保留字段 必须为0
     *RCODE(4 bit)  响应码 0无差错 3有差错*/
    unsigned short qdcount; //(2 bytes) 问题数 一般为1
    unsigned short ancount; //(2 bytes) 回答数 域名存在且未拦截则至少为1
    unsigned short nscount; //(2 bytes) 权威服务器数 一般为0
    unsigned short arcount; //(2 bytes) 附加记录数 一般为0
    void setHeader(char* buf)
    {
        unsigned short *temp=(unsigned short *)malloc(sizeof(unsigned short));
        memcpy(temp,buf,2);
        id=ntohs(*temp);
        memcpy(temp,&buf[2],2);
        flags=ntohs(*temp);
        memcpy(temp,&buf[4],2);
        qdcount=ntohs(*temp);
        memcpy(temp,&buf[6],2);
        ancount=ntohs(*temp);
        memcpy(temp,&buf[8],2);
        nscount=ntohs(*temp);
        memcpy(temp,&buf[10],2);
        arcount=ntohs(*temp);
        free(temp);
    }
    void print()
    {
        printf("    ID: 0x%x ",id);
        if(flags == 0x0100)
            printf("QR: 0 QPCODE: 0 AA: 0 TC: 0 RD: 1 RA: 0 Z: 0 RCODE: 0\n");
        else if(flags == 0x8180)
            printf("QR: 1 QPCODE: 0 AA: 0 TC: 0 RD: 1 RA: 1 Z: 0 RCODE: 0\n");
        else if(flags == 0x8183)
            printf("QR: 1 QPCODE: 0 AA: 0 TC: 0 RD: 1 RA: 1 Z: 0 RCODE: 3\n");
        else if(flags == 0x8100)
            printf("QR: 1 QPCODE: 0 AA: 0 TC: 0 RD: 1 RA: 0 Z: 0 RCODE: 0\n");
        else
            printf("FLAGS: 0x%x\n",flags);
        printf("    QDCOUNT: %d ANCOUNT: %d NSCOUNT: %d ARCOUNT: %d\n",qdcount,ancount,nscount,arcount);
    }
};

/**question part of query message*/
class Query
{
public:
    char transdomain[DOMAIN_LENGTH]; //(x bytes) 域名(3www5baidu3com0--www.baidu.com)
    unsigned short qtype; //(2 bvtes) 查询类型 1为ipv4,28为ipv6
    unsigned short qclass; //(2 bytes) 查询类 通常为1
};

/*RR part of response message
unsigned short name; //(2 bytes) 域名 通常被压缩为0xc00c
unsigned short type; //(2 bytes) 类型 1为ipv4,28为ipv6
unsigned short class; //(2 bytes) 类 通常为1
unsigned long ttl; //(4 bytes) 生存时间(自定义)
unsigned short rdlength; //(2 bytes) 资源数据长度(ipv4长度为4字节,ipv6长度为16字节)
unsigned long rdata; //(2 bytes) 存放找到的IP地址*/

/**IP_Domain structure*/
class IP_Domain
{
public:
    char IP[IP_LENGTH]; //IP地址
    char domain[DOMAIN_LENGTH]; //域名
};

/**ID translation structure*/
class IDtranslate
{
public:
    unsigned short oldID; //旧ID (IP_域名表中的下标)
    SOCKADDR_IN client_addr; //客户端套接字地址
    bool parsed; //标记是否完成解析
};

/**time of system*/
class Systime
{
public:
    SYSTEMTIME t;
    void printy() //从年份开始打印
    {
        GetLocalTime(&t);
        printf("%d-%d-%d %d:%d:%d:%d",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
    }
    void printh() //从小时开始打印
    {
        GetLocalTime(&t);
        printf("%d:%d:%d:%d",t.wHour,t.wMinute,t.wSecond,t.wMilliseconds);
    }
};

/**analyze command line parameters, modify some address or path*/
void analyze_cmd(int argc,char** argv,int& debug_lv,char* dns_ip,char* path);
/**init IP_Domain table,return actual size of the table*/
int init_IP_Domain(IP_Domain* table,char* path,int debug_lv);
/**analyze question part to get domain, qtype and qclass*/
void analyze_query(char* recvbuf,int recvlen,Query& query);
/**find index of array that matches domain by local DNS*/
int local_find(IP_Domain* table,int tablelen,char* domain);
/**print message in standard hexadecimal format*/
void print_message(char* buf,int buflen);
/**add new client information to transtable*/
unsigned short update_transtable(IDtranslate* transtable,int& amount,unsigned short oldid,SOCKADDR_IN client_addr);

/**补充知识*/
/*网络字节顺序: 大端法
 *主机字节顺序: 小端法 */
#endif // FUNCTIONS_H
