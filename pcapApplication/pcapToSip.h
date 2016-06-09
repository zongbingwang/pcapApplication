#pragma once

#include "pcapAnalyze.h"

//sip结构体信息
struct sipHeader
{
	u_int32	srcIP;			//sip会话的源IP地址 并不是指中间服务器
	u_int32	dstIP;			//sip会话的目的IP地址 并不是指中间服务器
	u_int16	srcMediaPort;	//RTP传输的源端口
	u_int16	dstMediaPort;	//RTP传输的目的端口

	bool INVITE_OK;			//是否收到INVITE的OK反馈
	bool BYE;				//是否发送结束信息
	bool BYE_OK;			//是否收到结束的反馈

	bool operator<(const sipHeader& __x) const
	{
		return (srcIP + dstIP + srcMediaPort + dstMediaPort) <
			(__x.srcIP + __x.dstIP + __x.srcMediaPort+__x.dstMediaPort);
	}

};

//RTP文件头结构体
struct rtpHeader
{
	/*
	版本号（V）：2比特，用来标志使用的RTP版本。
	填充位（P）：1比特，如果该位置位为1，则该RTP包的尾部就包含附加的填充字节。
	扩展位（X）：1比特，如果该位置位为1，则RTP固定头部后面就跟有一个扩展头部。
	CSRC计数器（CC）：4比特，含有固定头部后面跟着的CSRC的数目。
	*/
	u_int8	stream;
	u_int8	pt;			//负载类型
	u_int16 sn;			//序列号，按照这个排序
	u_int32 timeStamp;	//时间戳
	u_int32 ssrc;		//同步源标识符
	//u_int8  payLoad[0];	//负载信息
	u_int8  *payLoad;	//负载信息
	size_t  payLoadLen;	//长度
	bool	direction;  //标识方向, 0, 小的到大的， 1， 大的到小的

	//根据sn排序
	bool operator<(const rtpHeader& __x) const 
	{
		if (direction < __x.direction) return true;
		if (direction > __x.direction) return false;
		return (sn < __x.sn);
	}
};

//au头 https://en.wikipedia.org/wiki/Au_file_format
struct auHeader
{
	u_int32 magicNum;	//the value 0x2e736e64 (four ASCII characters ".snd")
	u_int32 dataOffset;	//the offset to the data in bytes, must be divisible by 8.
	u_int32 dataSize;	//data size in bytes. If unknown, the value 0xffffffff should be used.
	u_int32 encoding;	//Data encoding format:
	u_int32 sampleRate;	//the number of samples/second, e.g., 8000
	u_int32 channel;	//the number of interleaved channels, e.g., 1 for mono, 2 for stereo; more channels possible, but may not be supported by all readers.
};

class SIP:PCAP
{
public:
	SIP();
	~SIP();
	
	int start(string path, string pcapFile);

private:
	//由CALLID来确定会话,完善信息。。仅此而已
	map<string, sipHeader> CALLID2SIP;
	//由端口信息来确定CALLID
	map<sipHeader, string> SIP2CALLID;
	//由CALLID来确定的一组RTP通话，里面包含双方的通话，需要根据srcIP和dstIP提取
	map<string, vector<rtpHeader>> RTP_group;

	/*判断是否为SIP协议
	  -1:不是Sip协议
	  0:ack
	  1:invite
	  2:bye
	  3:1xx 临时应答，已接收
	  4:2xx 成功，已经正确处理
	  5:4xx 失败
	*/
	int isSip(u_int8 *data, size_t dataLen);

	//清空数据
	void init();

	//判断是否为RTP协议
	bool isRtp(size_t i, string & CALLID, bool & direction);

	////十六进制IP转成十进制IP的四地址表示
	string print_ip(u_int32 ip);

	//把ip1.ip2.ip3.ip4转化为u_int32
	u_int32 ip2u_Int32(u_int8 *data, size_t l, size_t r);

	//把端口转化为数字信息
	u_int16 SIP::port2u_Int16(u_int8 *data, size_t l, size_t r);

	//处理sip信息
	int sipInformationOutput(string path);

	//输出结构体信息
	void structOutput(string path);

	//查找CALLID
	string findCALLID(u_int8 *data, size_t dataLen);

	//查找srcIP或者dstIP
	u_int32 findSrcIPOrDstIP(u_int8 *data, size_t dataLen);

	//查找srcPort或者dstPort
	u_int16 findSrcPortOrDstPort(u_int8 *data, size_t dataLen);

	//输入，重载
	//int fileInput(string path, string pcapFile);

	//分析负载信息
	void analyzePayLoad(string path, string CALLID);
};