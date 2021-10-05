#include "functions.h"

void analyze_cmd(int argc,char** argv,int& debug_lv,char* dns_ip,char* path)
{
    int num;
    //对命令行参数的数量进行讨论
    switch(argc)
    {
    //至少有一个参数(程序名)
    case 1:
        debug_lv=0;
        break;
    //两个参数
    case 2:
        if(strcmp(argv[1],"-d") == 0)
            debug_lv=1;
        else if(strcmp(argv[1],"-dd") == 0)
            debug_lv=2;
        else //修改外部DNS或文件打开路径
        {
            debug_lv=0;
            //判断参数的第一个字符是否为数字
            num=argv[1][0]-'0';
            if(num>=0 && num<=9) //修改外部dns
                strcpy(dns_ip,argv[1]);
            else //修改文件代开路径
                strcpy(path,argv[1]);
        }
        break;
    //三个参数
    case 3:
        if(strcmp(argv[1],"-d") == 0)
        {
            debug_lv=1;
            num=argv[2][0]-'0';
            if(num>=0 && num<=9)
                strcpy(dns_ip,argv[2]);
            else
                strcpy(path,argv[2]);
        }
        else if(strcmp(argv[1],"-dd") == 0)
        {
            debug_lv=2;
            num=argv[2][0]-'0';
            if(num>=0 && num<=9)
                strcpy(dns_ip,argv[2]);
            else
                strcpy(path,argv[2]);
        }
        else //修改外部dns和文件打开路径
        {
            debug_lv=0;
            strcpy(dns_ip,argv[1]);
            strcpy(path,argv[2]);
        }
        break;
    //四个参数
    case 4:
        if(strcmp(argv[1],"-d") == 0)
            debug_lv=1;
        else
            debug_lv=2;
        strcpy(dns_ip,argv[2]);
        strcpy(path,argv[3]);
        break;
    default:
        printf("命令不合法!");
        exit(-1);
    }
    printf("*调试级别: %d\n",debug_lv);
    printf("*外部DNS服务器: %s:%d\n",dns_ip,PORT);
    printf("*配置文件打开路径: %s\n",path);
}
int init_IP_Domain(IP_Domain* table,char* path,int debug_lv)
{
    FILE *fp1=fopen(path,"r");
    if(fp1==NULL)
    {
        printf("Error: dnsrelay.txt文件打开失败！\n");
        exit(-1);
    }
    int i=0;
    while(!feof(fp1))
    {
        fscanf(fp1,"%s",table[i].IP);
        fscanf(fp1,"%s",table[i].domain);
        i++;
    }
    fclose(fp1);

    //调试等级为2要输出对照表
    if(debug_lv == 2)
    {
        printf("IP-域名对照表:\n");
        for(int j=0;j<i-1;j++)
            printf("%d:  %s-%s\n",j+1,table[j].IP,table[j].domain);
    }
    return i-1;
}
void analyze_query(char* recvbuf,int recvlen,Query& query)
{
    int mainlen=recvlen-12; //问题字段长度(报头长12字节)
    char* tempdomain=recvbuf+12; //域名起始地址
    int counter=0; //保存每一段域名的字符计数值
    int pos=0; //记录域名转换运作到的位置
    int index=0; //记录域名数组的下标
    while(pos<mainlen)
    {
        //当前字符表示字符计数值
        if(tempdomain[pos]>0 && tempdomain[pos]<64)
        {
            counter=tempdomain[pos];
            pos++;
            //该段域名添加到数组中
            while(counter)
            {
                query.transdomain[index++]=tempdomain[pos++];
                counter--;
            }
        }
        //移动到根标识符
        if(tempdomain[pos] == 0)
        {
            query.transdomain[index]='\0';
            pos++;
            break;
        }
        else
            query.transdomain[index++]='.';
    }
    unsigned short *temp=(unsigned short *)malloc(sizeof(unsigned short));
    memcpy(temp,&tempdomain[pos],2);
    query.qtype=ntohs(*temp);
    memcpy(temp,&tempdomain[pos+2],2);
    query.qclass=ntohs(*temp);
    free(temp);
}
int local_find(IP_Domain* table,int tablelen,char* domain)
{
    int index=-1;
    for(int i=0;i<tablelen;i++)
    {
        if(strcmp(table[i].domain,domain) == 0)
        {
            index=i;
            break;
        }
    }
    return index;
}
void print_message(char* buf,int buflen)
{
    printf("    ");
    for(int i=0;i<buflen;i++)
    {
        if((buf[i] & 0xf0) == 0x00)
            printf("0");
        printf("%x ",int(buf[i] & 0xff));
        if((i+1)%32 == 0)
            printf("\n    ");
    }
    printf("\n");
}
unsigned short update_transtable(IDtranslate* transtable,int& amount,unsigned short oldid,SOCKADDR_IN client_addr)
{
    int i=amount%ENTITIES;
    transtable[i].oldID=oldid;
    transtable[i].client_addr=client_addr;
    transtable[i].parsed=false;
    amount++;
    return (unsigned short)i;
}
