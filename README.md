# DNS服务器

（1）	初始化调试功能
静默模式
 
-d
 

-dd（打印IP_域名表）
 
 

（2）	不良网站拦截功能
	命令提示符中输入nslookup test0（转换表中IP为0.0.0.0）
 

	-d（输出时间坐标，序号，查询的域名，并对本地查询到的域名做*号标记）
 

	-dd（输出详细报文内容）
 

（3）	DNS服务器功能
	命令提示符输入nslookup bupt(IP地址在转换表中为123.127.134.10)
 

	-d（输出时间坐标，序号，查询的域名，并对本地查询到的域名做*号标记）
 

	-dd（输出详细报文内容）
 

(4)  中继功能
	命令提示符输入nslookup baidu.com(IP地址在转换表中没有对应域名)
 

	-dd输出详细报文内容与wireshark捕获的数据包对比
 

(5)  修改本地DNS服务器配置
	修改外部DNS服务器地址或配置文件打开路径
 
(6)  同时显示IPV4地址和IPV6地址
 
 

