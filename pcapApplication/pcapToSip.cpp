// pcapAnalyze.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "pcapToSip.h"

//初始化工作，清空内存
void SIP::init()
{
	package_list.clear();
	package_group.clear();
	CALLID2SIP.clear();
	SIP2CALLID.clear();
	RTP_group.clear();
}

//十六进制IP转成十进制IP的四地址表示
string SIP::print_ip(u_int32 ip)
{
	u_int8 bytes[4];
    string ip_str;
    char ip_cstr[16];

	//与前面的不一样
    bytes[3] = ip & 0xFF;
    bytes[2] = (ip >> 8) & 0xFF;
    bytes[1] = (ip >> 16) & 0xFF;
    bytes[0] = (ip >> 24) & 0xFF;
    sprintf_s(ip_cstr, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    ip_str = ip_cstr;
    return ip_str;
}

/*
//把32位的数字倒过来
inline u_int32 swapInt32(u_int32 value)
{
     return ((value & 0x000000FF) << 24) |
            ((value & 0x0000FF00) << 8)  |
            ((value & 0x00FF0000) >> 8)  |
            ((value & 0xFF000000) >> 24) ;
}

//把16位的数字倒过来
inline u_int16 swapInt16(u_int16 value)
{
     return ((value & 0x00FF) << 8) |
            ((value & 0xFF00) >> 8) ;
}
*/

//把ip1.ip2.ip3.ip4转化为u_int32
u_int32 SIP::ip2u_Int32(u_int8 *data, size_t l, size_t r)
{
	u_int32 sum=0, ip=0;

	for (size_t i = l; i <= r; i++)
	{
		if (data[i] == '.')
		{
			ip = (ip << 8) + sum;
			sum = 0;
			continue;
		}
		sum = 10 * sum + (data[i] - '0');
	}
	ip = (ip << 8) + sum;
	return ip;
}

//把端口转化为数字信息
u_int16 SIP::port2u_Int16(u_int8 *data, size_t l, size_t r)
{
	u_int16 port=0;

	for (size_t i = l; i <= r; i++)
	{
		port = 10 * port + (data[i] - '0');
	}
	return port;
}

SIP::SIP()
{

}

SIP::~SIP()
{

}

//判断是否为sip协议
int SIP::isSip(u_int8 *data, size_t dataLen)
{
	char s[15];
	memset(s,0,sizeof(s));
	for (size_t i = 0; i < 3; i++) s[i] = data[i];
	if (strcmp(s, "ACK") == 0) return 0;
	if (strcmp(s, "BYE") == 0) return 2;
	for (size_t i = 3; i < 6; i++) s[i] = data[i];
	if (strcmp(s, "INVITE") == 0) return 1;
	for (size_t i = 6; i < 11; i++) s[i] = data[i];
	if (strcmp(s, "SIP/2.0 100") == 0) return 3;
	if (strcmp(s, "SIP/2.0 180") == 0) return 3;
	if (strcmp(s, "SIP/2.0 183") == 0) return 4; //session progress 不是很理解，为什么出现这个状态
	if (strcmp(s, "SIP/2.0 200") == 0) return 4;
	if (strcmp(s, "SIP/2.0 404") == 0) return 5;

	return -1;
}

//判断是否为rtp协议
bool SIP::isRtp(size_t i, string & CALLID, bool & direction)
{
	//根据ip和端口判断
	u_int8  ipLen;
	u_int32 srcIP;
	u_int32 dstIP;
	u_int16 srcPort;
	u_int16 dstPort;

	memcpy(&srcIP, &package_list[i].pd->data[26], 4);
	memcpy(&dstIP, &package_list[i].pd->data[30], 4);
	srcIP = swapInt32(srcIP);
	dstIP = swapInt32(dstIP);
	
	memcpy(&ipLen, &package_list[i].pd->data[14], 1);
	ipLen = (ipLen & 0xF) << 0x2;
	
	memcpy(&srcPort, &package_list[i].pd->data[34 + ipLen - 20], 2);
	memcpy(&dstPort, &package_list[i].pd->data[36 + ipLen - 20], 2);
	srcPort = swapInt16(srcPort);
	dstPort = swapInt16(dstPort);

	sipHeader sip;
	sip.srcIP = srcIP;
	sip.dstIP = dstIP;
	sip.srcMediaPort = srcPort;
	sip.dstMediaPort = dstPort;
	sip.INVITE_OK = true;
	sip.BYE = false;
	sip.BYE_OK = false;
	if (sip.srcIP > sip.dstIP) 
	{
		swap(sip.srcIP, sip.dstIP);
		swap(sip.srcMediaPort, sip.dstMediaPort);
		direction = 1;
	}
	else 
	{
		direction = 0;
	}

	//端口信息在否在SIP2CALLID中
	if (SIP2CALLID.find(sip) != SIP2CALLID.end())
	{
		CALLID = SIP2CALLID[sip];
		return true;
	}
	else
		return false;
}

//查找CALLID
string SIP::findCALLID(u_int8 *data, size_t dataLen)
{
	string CALLID = "";
	string s = "Call-ID";
	for (size_t i = 7; i < dataLen; i++)
	{
		bool flag = true;
		for (size_t j = i - 7; j < i; j++)
			if (s[7-i+j] != data[j])
			{
				flag = false;
			}
		if (!flag) continue;

		for (size_t j = i + 2; ;j++)
		{
			if (data[j] == 0x0d)
			{
				break;
			}
			CALLID = CALLID +  (char)data[j];
		}
		break;
	}
	return CALLID;
}

//查找srcIP或者dstIP
u_int32 SIP::findSrcIPOrDstIP(u_int8 *data, size_t dataLen)
{
	u_int32 IP;
	string s = "c=IN IP4";
	for (size_t i = 8; i < dataLen; i++)
	{
		bool flag = true;
		for (size_t j = i - 8; j < i; j++)
			if (s[8-i+j] != data[j])
			{
				flag = false;
			}
		if (!flag) continue;

		size_t l = i + 1 ,r;
		for (size_t j = i + 1; ;j++)
		{
			if (data[j] == 0x0d)
			{
				r = j - 1;
				break;
			}
		}
		IP = ip2u_Int32(data, l, r);
		break;
	}
	return IP;
}

//查找srcPort或者dstPort
u_int16 SIP::findSrcPortOrDstPort(u_int8 *data, size_t dataLen)
{
	u_int16 Port;
	//string s = "m=audio";
	string s = "m=";
	for (size_t i = 2; i < dataLen; i++)
	{
		bool flag = true;
		for (size_t j = i - 2; j < i; j++)
			if (s[2-i+j] != data[j])
			{
				flag = false;
			}
		if (!flag) continue;

		size_t l = i + 6 ,r;
		for (size_t j = i + 6; ;j++)
		{
			if (data[j] == 0x20)
			{
				r = j - 1;
				break;
			}
		}
		Port = port2u_Int16(data, l, r);
		break;
	}
	return Port;
}


//浪费时间 以测试用例为例子 这个过程用了7秒，其它用了一秒
//结构体信息输出
void SIP::structOutput(string path)
{
	if (CALLID2SIP.empty()) return;

	map<string, sipHeader>::iterator it;
	for(it = CALLID2SIP.begin(); it != CALLID2SIP.end(); ++it) 
	{
		string CALLID = (*it).first;
		sipHeader SIP = (*it).second;
		if (RTP_group.find(CALLID) == RTP_group.end()) continue;

		//ofstream structData1, structData2;
		FILE* structData1 = NULL;
		FILE* structData2 = NULL;
		string data_name;
		string dir;
        ostringstream srcPort, dstPort;

		srcPort << dec << SIP.srcMediaPort;
		dstPort << dec << SIP.dstMediaPort;
		dir = path + "\\result\\sip-rtp-struct\\";
		vector<rtpHeader>::iterator it2 = RTP_group[CALLID].begin();

		//输出正向的
		if (it2 != RTP_group[CALLID].end() && (*it2).direction == 0)
		{
			data_name = dir + "SIP-RTP[" + print_ip(SIP.srcIP) + "][" + srcPort.str() + "][" + print_ip(SIP.dstIP) + "][" + dstPort.str() + "]0.txt";
			/*
			structData1.open(dir + data_name, ios::out | ios::binary);
			structData1 << "sip-rtp结构体信息：" << endl;
			structData1 << "[" << endl;
			structData1 << "	[protcol]:[sip]" << endl;
			structData1 << "	[srcIP]:[" << print_ip(SIP.srcIP) << "]" << endl;
			structData1 << "	[dstIP]:[" << print_ip(SIP.dstIP) << "]" << endl;
			structData1 << "	[srcPort]:[" << srcPort.str() << "]" << endl;
			structData1 << "	[dstPort]:[" << dstPort.str() << "]" << endl;
			structData1 << "]" << endl;
			structData1 << endl << endl;

			//输出包的结构体信息
			structData1 << "数据包信息：" << endl;
		

			for(; it2 != RTP_group[CALLID].end(); ++it2)
			{
				if ((*it2).direction == 1) break;

				structData1 << "[" << endl;
				structData1 << "	[stream]:[" << (int)(*it2).stream << "]" << endl;
				structData1 << "	[pt]:[" << (int)(*it2).pt << "]" << endl;
				structData1 << "	[sn]:[" << (int)(*it2).sn << "]" << endl;
				structData1 << "	[timeStamp]:[" << (*it2).timeStamp << "]" << endl;
				structData1 << "	[payLoadLen]:[" << (*it2).payLoadLen << "]" << endl;
				structData1 << "	[direction]:[" << (*it2).direction << "]" << endl;
				structData1 << "]" << endl;
				structData1 << endl << endl;
			}
			structData1.close();
			*/
			fopen_s(&structData1, data_name.c_str(), "w");
			fprintf(structData1, "sip: \n");
			fprintf(structData1, "[\n");
			fprintf(structData1, "	[protcol]:[sip]\n");
			fprintf(structData1, "  [srcIP]:[%s]\n", print_ip(SIP.srcIP).c_str());
			fprintf(structData1, "  [dstIP]:[%s]\n", print_ip(SIP.dstIP).c_str());
			fprintf(structData1, "  [srcPort]:[%s]\n", srcPort.str().c_str());
			fprintf(structData1, "  [dstPort]:[%s]\n", dstPort.str().c_str());
			fprintf(structData1, "]\n\n");

			//输出包的结构体信息
			fprintf(structData1, "rtp: \n");
		

			for(; it2 != RTP_group[CALLID].end(); ++it2)
			{
				if ((*it2).direction == 1) break;

				fprintf(structData1, "[\n");
				fprintf(structData1, "	[stream]:[%d]\n", (int)(*it2).stream);
				fprintf(structData1, "	[pt]:[%d]\n", (int)(*it2).pt);
				fprintf(structData1, "	[sn]:[%d]\n", (int)(*it2).sn);
				fprintf(structData1, "	[timeStamp]:[%d]\n", (int)(*it2).timeStamp);
				fprintf(structData1, "	[payLoadLen]:[%d]\n", (int)(*it2).payLoadLen);
				fprintf(structData1, "	[direction]:[%d]\n", (int)(*it2).direction);
				fprintf(structData1, "]\n\n");
			}
			fclose(structData1);
		}

		//输出反向的
		if (it2 != RTP_group[CALLID].end() && (*it2).direction == 1)
		{
			data_name = dir + "SIP-RTP[" + print_ip(SIP.srcIP) + "][" + srcPort.str() + "][" + print_ip(SIP.dstIP) + "][" + dstPort.str() + "]1.txt";
			/*
			structData2.open(dir + data_name, ios::out | ios::binary);

			structData2 << "sip-rtp结构体信息：" << endl;
			structData2 << "[" << endl;
			structData2 << "	[protcol]:[sip]" << endl;
			structData2 << "	[srcIP]:[" << print_ip(SIP.srcIP) << "]" << endl;
			structData2 << "	[dstIP]:[" << print_ip(SIP.dstIP) << "]" << endl;
			structData2 << "	[srcPort]:[" << srcPort.str() << "]" << endl;
			structData2 << "	[dstPort]:[" << dstPort.str() << "]" << endl;
			structData2 << "]" << endl;
			structData2 << endl << endl;

			//输出包的结构体信息
			structData2 << "数据包信息：" << endl;
		

			for(; it2 != RTP_group[CALLID].end(); ++it2)
			{
				structData2 << "[" << endl;
				structData2 << "	[stream]:[" << (int)(*it2).stream << "]" << endl;
				structData2 << "	[pt]:[" << (int)(*it2).pt << "]" << endl;
				structData2 << "	[sn]:[" << (int)(*it2).sn << "]" << endl;
				structData2 << "	[timeStamp]:[" << (*it2).timeStamp << "]" << endl;
				structData2 << "	[payLoadLen]:[" << (*it2).payLoadLen << "]" << endl;
				structData2 << "	[direction]:[" << (*it2).direction << "]" << endl;
				structData2 << "]" << endl;
				structData2 << endl << endl;
			}
			structData2.close();
			*/
			fopen_s(&structData2, data_name.c_str(), "w");
			fprintf(structData2, "sip: \n");
			fprintf(structData2, "[\n");
			fprintf(structData2, "	[protcol]:[sip]\n");
			fprintf(structData2, "  [srcIP]:[%s]\n", print_ip(SIP.srcIP).c_str());
			fprintf(structData2, "  [dstIP]:[%s]\n", print_ip(SIP.dstIP).c_str());
			fprintf(structData2, "  [srcPort]:[%s]\n", srcPort.str().c_str());
			fprintf(structData2, "  [dstPort]:[%s]\n", dstPort.str().c_str());
			fprintf(structData2, "]\n\n");

			//输出包的结构体信息
			fprintf(structData2, "rtp: \n");
		

			for(; it2 != RTP_group[CALLID].end(); ++it2)
			{
				fprintf(structData2, "[\n");
				fprintf(structData2, "	[stream]:[%d]\n", (int)(*it2).stream);
				fprintf(structData2, "	[pt]:[%d]\n", (int)(*it2).pt);
				fprintf(structData2, "	[sn]:[%d]\n", (int)(*it2).sn);
				fprintf(structData2, "	[timeStamp]:[%d]\n", (int)(*it2).timeStamp);
				fprintf(structData2, "	[payLoadLen]:[%d]\n", (int)(*it2).payLoadLen);
				fprintf(structData2, "	[direction]:[%d]\n", (int)(*it2).direction);
				fprintf(structData2, "]\n\n");
			}
			fclose(structData2);
		}
	}
}

//处理负载信息
void SIP::analyzePayLoad(string path, string CALLID)
{
	ofstream data1, data2;
    string data_name;
	string dir;
    ostringstream srcPort, dstPort;
	auHeader au;
	au.magicNum =	0x646e732e;
	au.dataOffset = 0x18000000;
	au.dataSize =	0xFFFFFFFF;
	au.encoding =	0x01000000;
	au.sampleRate = 0x401F0000;
	au.channel =	0x01000000;

	srcPort << dec << CALLID2SIP[CALLID].srcMediaPort;
	dstPort << dec << CALLID2SIP[CALLID].dstMediaPort;
    dir = path + "\\result\\sip-rtp-data\\";
	vector<rtpHeader>::iterator it = RTP_group[CALLID].begin();

	//写入负载信息0
	if (it != RTP_group[CALLID].end() && (*it).direction == 0)
	{
		data_name = "SIP-RTP[" + print_ip(CALLID2SIP[CALLID].srcIP) + "][" + srcPort.str() + "][" + print_ip(CALLID2SIP[CALLID].dstIP) + "][" + dstPort.str() + "]0.au";
		data1.open(dir + data_name, ios::out | ios::binary);

		if ((*it).pt == 0)
		{
			data1.write((char*)&au, sizeof(au));
		}
		for(; it != RTP_group[CALLID].end(); ++it)
		{
			if ((*it).direction == 1) break;
			data1.write((char*)(*it).payLoad, (*it).payLoadLen);
		}
		data1.close();
	}

	//写入负载信息1
	if (it != RTP_group[CALLID].end() && (*it).direction == 1)
	{
		data_name = "SIP-RTP[" + print_ip(CALLID2SIP[CALLID].srcIP) + "][" + srcPort.str() + "][" + print_ip(CALLID2SIP[CALLID].dstIP) + "][" + dstPort.str() + "]1.au";
		data2.open(dir + data_name, ios::out | ios::binary);
		
		if ((*it).pt == 0)
		{
			data2.write((char*)&au, sizeof(au));
		}
		for(; it != RTP_group[CALLID].end(); ++it)
		{
			data2.write((char*)(*it).payLoad, (*it).payLoadLen);
		}
		data2.close();
	}
}

//处理sip和rtp信息
int SIP::sipInformationOutput(string path)
{
	string CALLID;
	u_int32 srcIP;
	u_int32 dstIP;
	u_int16 srcPort;
	u_int16 dstPort;
	u_int16 frameType;
	u_int16 udpLen;
	u_int8  ipLen;
	size_t headerLen, dataLen;
	bool direction;

	for(size_t i = 0; i < package_list.size(); i++)
	{
		//首先判断是不是以太网帧（十进制为2048，十六进制0800）和UDP协议17,
		memcpy(&frameType, &package_list[i].pd->data[12], 2);
		frameType = swapInt16(frameType);
		if ((frameType != 2048) || (int) package_list[i].pd->data[23] != 17) continue;

		//处理负载信息
		//IP头首部长度
		memcpy(&ipLen, &(package_list[i]).pd->data[14], 1);
		ipLen = (ipLen & 0xF) << 0x2;
		
		//UDP包括负载信息的长度
		memcpy(&udpLen, &(package_list[i]).pd->data[38 + ipLen - 20], 2);
		udpLen = swapInt16(udpLen);
		headerLen = 14 + ipLen + 8;
		dataLen = udpLen - 8;

		//处理是否为sip协议
		int code = isSip((package_list[i]).pd->data + headerLen, dataLen);

		//INVITE
		if (code != -1)
		{
			//ack
			if (code == 0)
			{

			}
			//invite
			if (code == 1)
			{
				//CALLID
				CALLID = findCALLID((package_list[i]).pd->data + headerLen, dataLen);

				//已经加入???? 出错
				if (CALLID2SIP.find(CALLID) != CALLID2SIP.end()) continue;

				//srcIP
				srcIP = findSrcIPOrDstIP((package_list[i]).pd->data + headerLen, dataLen);

				//srcPort
				srcPort = findSrcPortOrDstPort((package_list[i]).pd->data + headerLen, dataLen);

				//加入map
				sipHeader SIP;
				SIP.srcIP = srcIP;
				SIP.srcMediaPort = srcPort;
				SIP.INVITE_OK = false;
				SIP.BYE = false;
				SIP.BYE_OK = false;
				
				CALLID2SIP.insert(make_pair(CALLID, SIP));
			}
			//BYE
			else if (code == 2)
			{
				//CALLID
				CALLID = findCALLID((package_list[i]).pd->data + headerLen, dataLen);

				//还没有加入??? 出错
				if (CALLID2SIP.find(CALLID) == CALLID2SIP.end()) continue;

				//BYE
				if (CALLID2SIP[CALLID].INVITE_OK != true) continue;
				CALLID2SIP[CALLID].BYE = true;
			}
			//trying
			else if (code == 3)
			{

			}
			//ok
			else if (code == 4)
			{
				//CALLID
				CALLID = findCALLID((package_list[i]).pd->data + headerLen, dataLen);

				//还没有加入??? 出错
				if (CALLID2SIP.find(CALLID) == CALLID2SIP.end()) continue;

				//判断是否已经BYE
				if (CALLID2SIP[CALLID].BYE)
				{
					sipHeader SIP;
					SIP = CALLID2SIP[CALLID];
					//没有RTP包需要处理
					if (RTP_group.find(CALLID) == RTP_group.end()) continue;

					if (SIP.INVITE_OK != true) continue;
					SIP.BYE_OK = true;

					//开始解析
					//排序
					sort(RTP_group[CALLID].begin(), RTP_group[CALLID].end());

					//分析
					analyzePayLoad(path, CALLID);

					//输出结构体信息
					structOutput(path);

					//删除
					SIP.BYE = false;
					SIP.BYE_OK = false;
					CALLID2SIP.erase(CALLID);
					SIP2CALLID.erase(SIP);
					RTP_group.erase(CALLID);
				}
				else
				{
					//SIP = CALLID2SIP[CALLID];

					//dstIP
					dstIP = findSrcIPOrDstIP((package_list[i]).pd->data + headerLen, dataLen);
					//dstPort
					dstPort = findSrcPortOrDstPort((package_list[i]).pd->data + headerLen, dataLen);
					CALLID2SIP[CALLID].dstIP = dstIP;
					CALLID2SIP[CALLID].dstMediaPort = dstPort;
					CALLID2SIP[CALLID].INVITE_OK = true;
					if (CALLID2SIP[CALLID].srcIP > CALLID2SIP[CALLID].dstIP) 
					{
						swap(CALLID2SIP[CALLID].srcIP, CALLID2SIP[CALLID].dstIP);
						swap(CALLID2SIP[CALLID].srcMediaPort, CALLID2SIP[CALLID].dstMediaPort);
					}

					sipHeader SIP;
					SIP = CALLID2SIP[CALLID];

					//加入SIP2CALLID
					SIP2CALLID.insert(make_pair(SIP, CALLID));
					CALLID2SIP[CALLID].INVITE_OK = true;
				}
			}
			//404
			else if (code == 5)
			{
				//CALLID
				CALLID = findCALLID((package_list[i]).pd->data + headerLen, dataLen);

				//还没有加入??? 出错
				if (CALLID2SIP.find(CALLID) == CALLID2SIP.end()) continue;
				
				//没有找到路径,删除之前存在的包
				CALLID2SIP.erase(CALLID);
			}
		}
		else if (dataLen >= 12 && isRtp(i, CALLID, direction))
		{
			//处理rtp协议
			rtpHeader RTP;
			size_t CSRC;

			memcpy(&RTP.stream, &package_list[i].pd->data[headerLen], 1);
			memcpy(&RTP.pt, &package_list[i].pd->data[headerLen + 1], 1);
			memcpy(&RTP.sn, &package_list[i].pd->data[headerLen + 2], 2);
			memcpy(&RTP.timeStamp, &package_list[i].pd->data[headerLen + 4], 4);
			memcpy(&RTP.ssrc, &package_list[i].pd->data[headerLen + 8], 4);
			RTP.pt = RTP.pt & 0x7F;
			RTP.sn = swapInt16(RTP.sn);
			RTP.timeStamp = swapInt32(RTP.timeStamp);
			RTP.ssrc = swapInt32(RTP.ssrc);
			RTP.direction = direction;

			CSRC = RTP.stream & 0xF;
			if (((RTP.stream >> 0x4) & 1) == 1)
			{
				size_t length;
				memcpy(&length, &package_list[i].pd->data[headerLen + 12 + CSRC * 4 + 2], 2);
				length = swapInt16(length);
				headerLen = headerLen + 12 + CSRC * 4 + 4 + length * 4;
				dataLen = dataLen - 12 - CSRC * 4 - length * 4;
			}
			else
			{
				headerLen = headerLen + 12 + CSRC * 4;
				dataLen = dataLen - 12 - CSRC * 4;
			}
			//const u_int32 total_len = static_cast<u_int32>(sizeof(rtpHeader) + dataLen);
			//RTP.payLoad = static_cast<rtpHeader*>(::malloc(total_len));

			//高危!!!!!!!!!!!!!!!!!!!!!
			RTP.payLoad = package_list[i].pd->data + headerLen;
			RTP.payLoadLen = dataLen;

			/*
			//求IP,端口 好蛋疼。。。
			u_int8  ipLen;
			u_int32 srcIP;
			u_int32 dstIP;
			u_int16 srcPort;
			u_int16 dstPort;

			memcpy(&srcIP, &package_list[i].pd->data[26], 4);
			memcpy(&dstIP, &package_list[i].pd->data[30], 4);
			srcIP = swapInt32(srcIP);
			dstIP = swapInt32(dstIP);
	
			memcpy(&ipLen, &package_list[i].pd->data[14], 1);
			ipLen = (ipLen & 0xF) << 0x2;
	
			memcpy(&srcPort, &package_list[i].pd->data[34 + ipLen - 20], 2);
			memcpy(&dstPort, &package_list[i].pd->data[36 + ipLen - 20], 2);
			srcPort = swapInt16(srcPort);
			dstPort = swapInt16(dstPort);

			//求得CALLID
			sipHeader SIP;
			SIP.srcIP = srcIP;
			SIP.dstIP = dstIP;
			SIP.srcMediaPort = srcPort;
			SIP.dstMediaPort = dstPort;
			SIP.INVITE_OK = true;
			SIP.BYE = false;
			SIP.BYE_OK = false;
			
			if (SIP2CALLID.find(SIP) == SIP2CALLID.end()) continue;
			*/
			//插入队列中
			RTP_group[CALLID].push_back(RTP);
		}
		else
		{
			//否则退出这个处理
			continue;
		}
	}
	return 0;
}


//暂定只处理音频
int SIP::start(string path, string pcapFile)
{
	//long beginTime =clock();//获得开始时间，单位为毫秒

	init();
	if (fileInput(path, pcapFile))
	{
		sipInformationOutput(path);
	}
	else
	{
		//cout << "failed" << endl;
		return -1;
	}
	
	//long endTime=clock();//获得结束时间
    //cout<<"beginTime:"<<beginTime<<endl
    //    <<"endTime:"<<endTime<<endl
    //    <<"endTime-beginTime:"<<endTime-beginTime<<endl;
	return 0;
}