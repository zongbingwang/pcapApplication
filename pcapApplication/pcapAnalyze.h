#pragma once

#include "stdafx.h"
using namespace std;

typedef unsigned long	u_int32;
typedef unsigned short	u_int16;
typedef unsigned char	u_int8;

//pcap文件头结构体,24个byte
struct fileHeader
{
	u_int32 magic;			// 标识位，这个标识位的值是16进制的 0xa1b2c3d4（4个字节）
	u_int16 magorVersion;	// 主版本号（2个字节）
    u_int16	minorVersion;	// 副版本号（2个字节）
	u_int32 timezone;       // 区域时间（4个字节）
	u_int32 sigflags;       // 精确时间戳（4个字节）
    u_int32 snaplen;        // 数据包最大长度（4个字节）
	u_int32 linktype;       // 链路层类型（4个字节）

};

//pcap文件中的数据包头,16个byte
struct dataHeader
{
	/**
     * 时间戳（秒）：记录数据包抓获的时间
     * 记录方式是从格林尼治时间的1970年1月1日 00:00:00 到抓包时经过的秒数（4个字节）
     */
	u_int32 timeS;  
    /**
     * 时间戳（微秒）：抓取数据包时的微秒值（4个字节）
     */
    u_int32 timeMs;                     
    /**
     * 数据包长度：标识所抓获的数据包保存在 pcap 文件中的实际长度，以字节为单位（4个字节）
     */
    u_int32 caplen;
    /**
     * 数据包实际长度： 所抓获的数据包的真实长度（4个字节）
     * 如果文件中保存不是完整的数据包，那么这个值可能要比前面的数据包长度的值大。
     */
	u_int32 len;                        
};

//数据帧头：以太网帧，可能会携带延迟信息,14个byte
struct frameHeader
{
	u_int8	dstMac[6];		//目的MAC地址
	u_int8	srcMac[6];		//源MAC地址
	u_int16 frameType;		//数据帧类型
};

//IP数据包,最小长度为20byte
struct ipHeader
{
	/*
	版本+报头长度
	协议版本号(4 bit)及包头长度(4bit) =（1 字节)
	版本号(Version):一般的值为0100（IPv4），0110（IPv6）
	*/
	u_int8	varHLen;
    u_int8	tos;			//服务类型
	u_int16	totalLen;       //总长度
	u_int16	id;				//标识
	u_int16	flagSegment;    //标志+片偏移
	u_int8	ttl;            //生存周期
	u_int8	protocol;       //协议类型
	u_int16	checkSum;       //头部校验和
	u_int32	srcIP;			//源IP地址
	u_int32	dstIP;			//目的IP地址
};

//TCP数据包，最小长度为20byte
struct tcpHeader
{
	u_int16	srcPort;		//源端口
	u_int16	dstPort;		//目的端口
	u_int32	seq;			//序号
	u_int32	ack;			//确认号
	u_int8	headerLen;		//数据报头的长度(4 bit) + 保留(4 bit)
	u_int8	flags;			//标识TCP不同的控制消息
	u_int16	window;			//窗口大小
	u_int16	checkSum;		//校验和
	u_int16	urgentPointer;  //紧急指针
};

//UDP数据包，最小长度为8byte
struct udpHeader
{
	u_int16 srcPort;		//源端口
	u_int16 dstPort;        //目的端口
	u_int16 len;			//数据包长
	u_int16 checkSum;		//校验和
};

//数据包信息
struct pcap_data
{
	u_int32 len;		    //捕获的总长度，可能带有padding
	u_int32 seq;			//seq
	u_int32 ack;			//ack
	u_int8  data[0];		//特殊用法，保存数据包
};

//数据包
struct package
{
	bool direction;		    //从小的ip传到大的ip方向为0，否则方向为1
	dataHeader ph;
    pcap_data *pd;

	bool operator<(const package& __x) const 
	{
		return (pd->ack + pd->seq) < 
			(__x.pd->ack + __x.pd->seq);
	}
};

//五元组
struct five
{
    u_int8	protcol;
	u_int32 srcIP;
	u_int32 dstIP;
	u_int16 srcPort;
	u_int16 dstPort;

    bool operator<(const five& __x) const 
	{
		return (srcIP + dstIP + srcPort + dstPort) <
			(__x.srcIP + __x.dstIP + __x.srcPort+__x.dstPort);
    }
};

class  PCAP
{
public:
	 PCAP();
	~ PCAP();
	int start(string path, string pcapFile);

protected:
	map<five, vector<package>> package_group;
	vector<package> package_list;
	fileHeader pfh;

	//十六进制IP转成十进制IP的四地址表示
	string print_ip(u_int32 ip);

	//把32位的数字倒过来
	u_int32 swapInt32(u_int32 value);

	//把16位的数字倒过来
	u_int16 swapInt16(u_int16 value);

	//初始化工作，清空内存
	void init();

	//pcap包输入
	int fileInput(string path, string pcapFile);

	//pcap包分类
	void pcapDivideIntoGroups();

	//分组pcap包输出
	void groupsOutput(string path);

	//结构体信息输出
	void structOutput(string path);

	//负载信息输出
	void informationOutput(string path);
};