#include "functions.h"

int main(int argc,char** argv)
{
    Systime time1;
    time1.printy();
    printf("\n打开DNS中继服务器...\n");

    //1.分析命令行参数
    int debug_level; //调试等级(0-2)
    char extdns_ip[IP_LENGTH]=EXTERNAL_DNS; //外部DNS服务器的IP地址
    char open_path[PATH_LENGTH]=DEFAULT_PATH; //配置文件的打开路径
    analyze_cmd(argc,argv,debug_level,extdns_ip,open_path);

    //2.初始化IP_域名对照表,j建立ID转换表
    IP_Domain dnstable[ENTITIES]; //本地DNS服务器的IP_域名对照表
    int entity=init_IP_Domain(dnstable,open_path,debug_level); //得到实际表长
    IDtranslate transtable[ENTITIES]; //ID转换表,下标为新ID
    int amount=0; //ID转换表已加入对象的个数

    //3.搭建环境并建立套接字
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2,2),&wsadata);
    SOCKET server_sock; //该程序做服务器的套接字
    SOCKET client_sock; //该程序做客户端的套接字
    server_sock=socket(AF_INET,SOCK_DGRAM,0); //AF_INET-IPV4
    client_sock=socket(AF_INET,SOCK_DGRAM,0);
    if(server_sock == INVALID_SOCKET)
    {
        printf("Error: server_sock套接字建立失败！\n");
        exit(1);
    }
    if(client_sock == INVALID_SOCKET)
    {
        printf("Error: client_sock套接字建立失败！\n");
        exit(1);
    }

    //4.构建服务器与客户端的地址并绑定对应套接字
    /**本地DNS服务器地址*/
    SOCKADDR_IN local_server_addr;
    memset(&local_server_addr,0,sizeof(local_server_addr));
    local_server_addr.sin_family=AF_INET;
    local_server_addr.sin_addr.s_addr=htonl(INADDR_ANY); //代表本机所有IP地址 访问127.0.0.1也可以访问到该地址(本机回测)
    local_server_addr.sin_port=htons(PORT); //通过上面的地址找到对应电脑后,通过该接口找到本地DNS服务器这个程序
    if(bind(server_sock,(SOCKADDR*)&local_server_addr,sizeof(local_server_addr))) //绑定本地DNS服务器
    {
        printf("Error: server_sock绑定本地DNS服务器地址失败: %d\n",WSAGetLastError());
        exit(-2);
    }
    /**本地DNS客户端地址*/
    SOCKADDR_IN local_client_addr; //本地向外部DNS发出请求时作为客户端
    memset(&local_client_addr,0,sizeof(local_client_addr));
    local_client_addr.sin_family=AF_INET;
    local_client_addr.sin_port=htons(PORT+1); //作为客户端时端口号54
    local_client_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(client_sock,(SOCKADDR*)&local_client_addr,sizeof(local_client_addr))) //绑定本地DNS客户端
    {
        printf("Error: client_sock绑定本地DNS客户端地址失败: %d\n",WSAGetLastError());
        exit(-3);
    }
    /**外部DNS服务器地址*/
    SOCKADDR_IN extserver_addr;
    int extserver_len=sizeof(extserver_addr);
    extserver_addr.sin_family=AF_INET;
    extserver_addr.sin_port=htons(PORT);
    extserver_addr.sin_addr.s_addr=::inet_addr(extdns_ip); //兼容IPV4和IPV6地址表示法
    /**(外部)客户端地址*/
    SOCKADDR_IN extclient_addr;
    int extclient_len=sizeof(extclient_addr);

    //5.接收客户端发来的查询报文并发送响应报文回复
    char recvbuf[BUF_SIZE]; //接收报文缓冲区
    char sendbuf[BUF_SIZE]; //发送报文缓冲区
    Header header; //报文头部
    Query query; //查询报文问题部分
    memset(recvbuf,0,BUF_SIZE);
    printf("DNS中继服务器成功运行...\n");
    int seq=0; //收到消息的序号

    while(true) //阻塞
    {
        int recvlen=recvfrom(server_sock,recvbuf,BUF_SIZE,0,(SOCKADDR*)&extclient_addr,&extclient_len); //返回接收到的字符数
		//设置发送超时
		setsockopt(server_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)& TIMEOUT, sizeof(int));
		setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)& TIMEOUT, sizeof(int));
		//设置接收超时
		setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)& TIMEOUT, sizeof(int));
		setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)& TIMEOUT, sizeof(int));
		if(recvlen == 0)
        {
            printf("Error: 与客户端连接中断！\n");
            break;
        }
        else if(recvlen == SOCKET_ERROR)
        {
          //printf("Error: 未成功接收消息！\n");
            continue;
        }
        else //成功接收消息
        {
            //打印调试信息
            if(debug_level)
            {
                if(debug_level == 2)
                    printf("\n");
                time1.printh();
                printf("   %d:",seq);
                seq++;
            }
            int findi=-1;

            //5.0忽略类型不是ipv4的报文
            analyze_query(recvbuf,recvlen,query);
            header.setHeader(recvbuf);

            //5.1匹配域名和IP地址
            findi=local_find(dnstable,entity,query.transdomain);

            //5.2在本地找到对应的IP,构造响应报文
            if(findi!=-1)
            {
                if(query.qtype == 1)
                {
                    if(debug_level)
                    {
                        printf("* %s  QTYPE: %d QCLASS: %d\n",query.transdomain,query.qtype,query.qclass);
                        if(debug_level == 2)
                        {
                            printf("Receive from %s:%d <Query>\n",inet_ntoa(extclient_addr.sin_addr),ntohs(extclient_addr.sin_port));
                            header.print();
                            print_message(recvbuf,recvlen);
                        }
                    }
                    for(int i=0;i<recvlen;i++)
                        sendbuf[i]=recvbuf[i];

                    //5.2.1构造头部
                    unsigned short tempf; //temp flags
                    unsigned short tempa; //temp ancount
                    if(strcmp(dnstable[findi].IP,"0.0.0.0") == 0) //不良网站拦截功能
                    {
                        tempf=htons(0x8183); //(QR=1 QPCODE=0000 AA=0 TC=0 RD=1 RA=1 Z=000 RCODE=0011) 差错报文
                        tempa=htons(0x0000); //ancount=0
                    }
                    else
                    {
                        tempf=htons(0x8180); //(QR=1 QPCODE=0000 AA=0 TC=0 RD=1 RA=1 Z=000 RCODE=0000) 无错报文
                        tempa=htons(0x0001); //ancount=1
                    }
                    memcpy(&sendbuf[2],&tempf,2);
                    memcpy(&sendbuf[6],&tempa,2);
                    //nscount arcount question不处理

                    //5.2.2构造响应报文的资源记录RR
                    int sendlen=recvlen;
                    unsigned short temp2;
                    unsigned long temp4;
                    temp2=htons(0xc00c);
                    memcpy(&sendbuf[sendlen],&temp2,2); //Name 压缩的结果
                    sendlen+=2;
                    temp2=htons(0x0001);
                    memcpy(&sendbuf[sendlen],&temp2,2); //TYPE=1
                    sendlen+=2;
                    temp2=htons(0x0001);
                    memcpy(&sendbuf[sendlen],&temp2,2); //cLASS=1
                    sendlen+=2;
                    temp4=htonl(0x00000100);
                    memcpy(&sendbuf[sendlen],&temp4,4); //TTL=256s
                    sendlen+=4;
                    temp2=htons(0x0004);
                    memcpy(&sendbuf[sendlen],&temp2,2); //RDLENGTH=4
                    sendlen+=2;
                    temp4=(unsigned long)inet_addr(dnstable[findi].IP);
                    memcpy(&sendbuf[sendlen],&temp4,4); //RDATA
                    sendlen+=4;

                    if(debug_level == 2)
                    {
                        printf("Send to %s:%d <Response>\n",inet_ntoa(extclient_addr.sin_addr),extclient_addr.sin_port);
                        Header rheader;
                        rheader.setHeader(sendbuf);
                        //print_header(rheader);
                        rheader.print();
                        print_message(sendbuf,sendlen);
                    }

                    //5.2.2发送响应报文到客户端
                    int sendlen1=sendto(server_sock,sendbuf,sendlen,0,(SOCKADDR*)&extclient_addr,extclient_len);
                    if(sendlen1<=0)
                    {
                        if(debug_level)
                            printf("Error: 发送响应报文到客户端失败: %d\n",WSAGetLastError());
                    }
                }
                else
                    goto flag1;
            }

            //5.3没有在本地找到域名,需要转发给外部DNS服务器,接收到响应报文后对客户端做出响应
            else
            {
                flag1:
                if(debug_level)
                {
                    printf("  %s  QTYPE: %d QCLASS: %d\n",query.transdomain,query.qtype,query.qclass);
                    if(debug_level == 2)
                    {
                        printf("Receive from %s:%d <Query>\n",inet_ntoa(extclient_addr.sin_addr),ntohs(extclient_addr.sin_port));
                        header.print();
                        print_message(recvbuf,recvlen);
                    }
                }

                //5.3.1新旧ID的转换与记录,修改的查询报文转发到外部DNS服务器并等待响应
                unsigned short *oldid=(unsigned short *)malloc(sizeof(unsigned short));
                memcpy(oldid,recvbuf,2);
                unsigned short i=update_transtable(transtable,amount,ntohs(*oldid),extclient_addr);
                unsigned short newid=htons(i+OFFSET);
                memcpy(recvbuf,&newid,2); //更改ID
                if(debug_level == 2)
                    printf("Send to %s:%d <Query> ID(0x%x —> 0x%x)\n",inet_ntoa(extserver_addr.sin_addr),ntohs(extserver_addr.sin_port),ntohs(*oldid),i+OFFSET);
                free(oldid);
                int sendlen=sendto(client_sock,recvbuf,recvlen,0,(SOCKADDR*)&extserver_addr,sizeof(extserver_addr)); //将客户端发来的报文转发给外部DNS服务器
                if(sendlen == SOCKET_ERROR)
                {
                    if(debug_level)
                        printf("Error: 发送消息到外部DNS服务器超时！\n");
                    continue;
                }
                else if(sendlen == 0)
                {
                    if(debug_level)
                        printf("Error: 与外部DNS服务器连接中断！\n");
                    break;
                }
                int recvlenr=recvfrom(client_sock,recvbuf,BUF_SIZE,0,(SOCKADDR*)&extserver_addr,&extserver_len); //从外部DNS服务器接收响应报文
                if(recvlenr == 0)
                {
                    if(debug_level == 1)
                        printf("Error: 与外部DNS服务器连接中断！\n");
                    break;
                }
                else if(recvlenr == SOCKET_ERROR)
                {
                    if(debug_level)
                        printf("Error: request timed out！\n");
                    continue;
                }

                //5.3.2对接收到的响应报文进行合理的判断筛选
                //收到外部DNS服务器的响应报文,需要判断
                //响应可能有延迟,当前收到的响应报文未必是刚刚查询的,该ID的响应报文可能(分段)发给本地多次,不做重复解析
                else
                {
                    unsigned short *newid1=(unsigned short *)malloc(sizeof(unsigned short));
                    memcpy(newid1,recvbuf,2);
                    int newid2=(int)(ntohs(*newid1)-OFFSET);
                    free(newid1);
                    if(transtable[newid2].parsed)
                        continue; //当前查询已解析则跳过
                    if(debug_level == 2)
                    {
                        printf("Receive from %s:%d <Response>\n",inet_ntoa(extserver_addr.sin_addr),ntohs(extserver_addr.sin_port));
                        Header rheader;
                        rheader.setHeader(recvbuf);
                        rheader.print();
                        print_message(recvbuf,recvlenr);
                    }
                    unsigned short oldid1=htons(transtable[newid2].oldID);
                    memcpy(recvbuf,&oldid1,2);
                    transtable[newid2].parsed=true;
                    if(debug_level == 2)
                        printf("Send to %s:%d <Response> ID(0x%x —> 0x%x)\n",inet_ntoa(extclient_addr.sin_addr),ntohs(extclient_addr.sin_port),newid2+OFFSET,transtable[newid2].oldID);
                    int sendlen1=sendto(server_sock,recvbuf,recvlenr,0,(SOCKADDR*)&transtable[newid2].client_addr,sizeof(transtable[newid2].client_addr)); //本地DNS转发到客户端
                    if(sendlen1 == SOCKET_ERROR)
                    {
                        if(debug_level)
                            printf("Error: 中继转发消息给客户端超时\n");
                        continue;
                    }
                    else if(sendlen1 == 0)
                    {
                        if(debug_level)
                            printf("Error: 与客户端连接中断！\n");
                        break;
                    }
                }
            }
        }
    }

    //6.关闭套接字和环境
    closesocket(server_sock);
    closesocket(client_sock);
    WSACleanup();
    
    return 0;
}
