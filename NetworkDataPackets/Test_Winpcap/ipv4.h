/*************************************************************
*
*	互联网协议第三层 网络层 IPv4 结构数据
*	参考：https://zh.wikipedia.org/wiki/IPv4
*
*	高低字节序转换（htonl、ntohl、htons、ntohs函数）
*	htons 把uint16_t类型从主机序转换到网络序
*	htonl 把uint32_t类型从主机序转换到网络序
*	ntohs 把uint16_t类型从网络序转换到主机序
*	ntohl 把uint32_t类型从网络序转换到主机序
*
*/

#pragma once
#include <stdio.h>
#include <stdint.h>
#include <winsock.h>


/*
	网络层 IPv4 结构数据
*/
typedef struct ipv4_header
{
	//版本信息(前4位)，报头长度(后4位)
	//Version（版本）：占4比特，用来表明IP协议实现的版本号，当前一般为IPv4，即0100。
	//Internet Header Length(IHL)（报头长度）：占4比特，表示头部占32比特的长度是多少，比如说不包含任何选项的IP数据报，到 Destination Address为止，32x5=160比特=20字节，此字段最大值为60字节。
	uint8_t		VersionAndHeaderLen;

	//区分服务（Differentiated Services，DS）。占6bit，最初被定义为服务类型字段，实际上并未使用，但1998年被IETF重定义为区分服务RFC 2474。只有在使用区分服务时，这个字段才起作用，在一般的情况  下都不使用这个字段。例如需要实时数据流的技术会应用这个字段，一个例子是VoIP。
	//显式拥塞通告（ Explicit Congestion Notification，ECN）。占低2位
	uint8_t		DSAndECN;

	//总长度字段。占16比特，指明整个数据报的长度（以字节为单位）。最大长度为65535字节。
	uint16_t	TotalLength;

	//标识。占16比特，用来唯一地标识主机发送的每一份数据报。通常每发一份报文，它的值会加1。
	uint16_t	Identification;

	//标志位与片断偏移。
	//Flags标志占3比特，表示这份报文是否需要分片传输。
	//Fragment Offset
	uint16_t	FlagsAndFragment;

	//Time to live(TTL)生存期。占8比特，用来表示该数据报文最多可以经过的路由器数，没经过一个路由器都减1，直到为0数据包丢掉。
	uint8_t		TTL;

	//第四层传输层协议字段。占8比特，用来指出IP层所封装的上层协议类型，如传输层TCP/UDP/ICMP/IGMP等。
	uint8_t		Protocol;

	//头部校验和字段。占16比特，内容是根据IP头部计算得到的校验和码。
	//计算方法是：对头部中每个16比特进行二进制反码求和。（和ICMP、IGMP、TCP、UDP不同，IP不对头部后的数据进行校验）。
	uint16_t	Checksum;

	//源地址.占32字节，针对IPV4
	uint32_t	SrcAddr;

	//目的地址。占32字节，针对IPV4
	uint32_t	DstAddr;

	//可选项字段。占32比特，用来定义一些任选项：如记录路径、时间戳等。这些选项很少被使用，同时并不是所有主机和路由器都支持这些选项。
	//可选项字段的长度必须是32比特的整数倍，如果不足，必须填充0以达到此长度要求。
	//uint32_t	Options;		
} IPv4_Header;

/*
	IP服务类型
*/
typedef enum ipv4_type_of_service
{
	ECN_CE = 0x01,		//ECN-CE

	ECN_CT = 0x02,		//ECN-Capable Transport(ECT)

}IPv4_Type_Of_Service;

/*
	IPv4结构分片标志信息。占3位字段用于控制和识别分片
*/
typedef enum ipv4_fragment_flags
{
	//更多分片（More Fragment，MF），MF=1代表后面还有分片，MF=0 代表已经是最后一个分片。
	MoreFragment = 0x01,

	//禁止分片（Don’t Fragment，DF），当DF=0时才允许分片
	DontFragment = 0x02,

	//保留，必须为0
	//Reserved = 0x04,
	
}IPv4_Fragment_Flags;


/*

	功能描述	:	获取 IPv4 版本，位于结构字段 VersionAndHeaderLen 中，高4位
	输入参数	:	const IPv4_Header *header
	输出参数	:	无
	返 回 值	:	返回 IPv4 的版本号

*/
static uint8_t get_ipv4_version(const IPv4_Header *header)
{
	return (header->VersionAndHeaderLen & 0xF0) >> 4;
}

/*

	功能描述	:	获取 IPv4 结构数据长度，跟据协议 IPv4 结构数据是一个可变长度的结构。位于结构字段 VersionAndHeaderLen 中，低4位，最大值0x0F * 4 = 60，最大60字节
	输入参数	:	const IPv4_Header *header
	输出参数	:	无
	返 回 值	:	返回 IPv4 结构数据长度

*/
static uint8_t get_ipv4_length(const IPv4_Header *header)
{
	return (header->VersionAndHeaderLen & 0x0F) * 4;
}


/*

	功能描述	:	获取 IPv4 结构中分片标志位，位于结构字段 FlagsAndFragment 中，高3位
	输入参数	:	const IPv4_Header *header
	输出参数	:	无
	返 回 值	:	返回 IPv4 分片标志值，参考：IPv4_Fragment_Flags

*/
static uint8_t get_ipv4_fragment_flags(const IPv4_Header *header)
{
	return (htons(header->FlagsAndFragment) & 0xE000) >> 13;
}


/*

	功能描述	:	获取 IPv4 结构中 Fragment Offset 信息，位于结构字段 FlagsAndFragment 中，低13位
	输入参数	:	const IPv4_Header *header
	输出参数	:	无
	返 回 值	:	返回 Fragment Offset 值

*/
static uint16_t get_ipv4_fragment_offset(const IPv4_Header *header)
{
	return htons(header->FlagsAndFragment) & 0x1FFF;
}

/*

	功能描述	:	获取 IPv4 结构中 传输层协议字符串
	输入参数	:	int value 协议值，参考：winsock.h Protocols
	输出参数	:	无
	返 回 值	:	返回 IPv4 传输层协议字符串形式

*/
static char* get_ipv4_protocol_char(int value)
{
	switch (value)
	{
	case IPPROTO_IP:	return "IP";
	case IPPROTO_ICMP:	return "ICMP";
	case IPPROTO_IGMP:	return "IGMP";
	case IPPROTO_GGP:	return "GGP";
	case IPPROTO_TCP:	return "TCP";
	case IPPROTO_PUP:	return "IPUP";
	case IPPROTO_UDP:	return "UDP";
	case IPPROTO_IDP:	return "IDP";
	case IPPROTO_ND:	return "ND";
	case IPPROTO_RAW:	return "IRAW";
	case IPPROTO_MAX:	return "MAX";
	}

	return "UNKNOW";
}

/*

	功能描述	:	获取 IPv4 结构中 传输层协议字符串
	输入参数	:	const IPv4_Header *header
	输出参数	:	无
	返 回 值	:	返回 IPv4 传输层协议字符串形式

*/
static char* get_ipv4_protocol_char(const IPv4_Header *header)
{
	return get_ipv4_protocol_char(header->Protocol);
}

/*

	功能描述	:	获取 IPv4 结构数据校验和
	输入参数	:	const IPv4_Header *header
	输出参数	:	无
	返 回 值	:	返回 数据校验结果正确与否

*/
static bool checksum_ipv4_header(const IPv4_Header *header)
{
	uint8_t size = sizeof(IPv4_Header);
	uint8_t *raw = (uint8_t*)header;
	//uint8_t *raw = (uint8_t*)malloc(size);	
	//memcpy(raw, header, sizeof(IPv4_Header));

	uint32_t sum = 0;

	for (uint8_t i = 0; i < size; i+=2)
		sum += (raw[i] << 8) | raw[i + 1];		//每16bit二进制求和
	
	sum -= htons(header->Checksum);				//减掉原校验值，检验的结果等于原检验值，如果不减，检验结果为0，即数据正确
	
	sum = (sum >> 16) + (sum & 0xFFFF);			//高16bit和低16bit相加，直到高16位为0
	sum += (sum >> 16);							//直到高16位为0

	//free(raw);
	//printf("check sum: 0x%02X \n", (uint16_t)(~sum));

	return (uint16_t)(~sum) == htons(header->Checksum);
}

/*

	功能描述	:	获取 IPv4 ip地址
	输入参数	:	uint32_t value ， 小端格式 低->高
	输出参数	:	char *addr 输出ip地址的字符串形式，addr长度不得小于16
	返 回 值	:	返回 ip地址的字符串形式

*/
static char* get_ipv4_address(uint32_t value, char *addr)
{
	sprintf_s(addr, 16, "%d.%d.%d.%d", (value & 0xFF000000) >> 24, (value & 0x00FF0000) >> 16, (value & 0x0000FF00) >> 8, value & 0xFF);
	return addr;
}

/*

	功能描述	:	获取 IPv4 结构数据中源ip地址的字符串形式
	输入参数	:	uint32_t value ， 小端格式 低->高
	输出参数	:	无
	返 回 值	:	返回 ip地址的字符串形式

*/
static char* get_ipv4_src_address(const IPv4_Header *header)
{
	static char src[16];
	memset(src, 0x00, 16);
	return get_ipv4_address(htonl(header->SrcAddr), src);
	//return src;
}

/*

	功能描述	:	获取 IPv4 结构数据中目的ip地址的字符串形式
	输入参数	:	uint32_t value ， 小端格式 低->高
	输出参数	:	无
	返 回 值	:	返回 ip地址的字符串形式

*/
static char* get_ipv4_dst_address(const IPv4_Header *header)
{
	static char dst[16];
	memset(dst, 0x00, 16);
	return get_ipv4_address(htonl(header->DstAddr), dst);
	//return dst;
}

/*

功能描述	:	测试输出 IPv4 结构数据原始字节数据
输入参数	:	const IPv4_Header *header
输出参数	:	无
返 回 值	:	无

*/
static void print_ipv4_raw(const IPv4_Header *header)
{
	uint8_t size = sizeof(ipv4_header);
	uint8_t *buffer = (uint8_t*)malloc(size);
	memcpy(buffer, header, size);

	for (int i = 0; i < size; i++)	
		printf("%02X ", buffer[i]);
	printf("\n");

	free(buffer);
}

/*

	功能描述	:	测试输出 IPv4 结构数据信息
	输入参数	:	const IPv4_Header *header
	输出参数	:	无
	返 回 值	:	无

*/
static void print_ipv4_info(const IPv4_Header *header)
{
	uint8_t flags = get_ipv4_fragment_flags(header);

	printf("+Internet Protocol, Source: %s  Destination: %s\n", get_ipv4_src_address(header), get_ipv4_dst_address(header));
	printf("\tVersion: %d\n", get_ipv4_version(header));
	printf("\tHeader Length: %d bytes\n", get_ipv4_length(header));
	printf("\tDifferentiated Services Failed: 0x%02X\n", header->DSAndECN);
	printf("\tTotal Length: %d\n", htons(header->TotalLength));
	printf("\tIdentification: 0x%02X (%d)\n", htons(header->Identification), htons(header->Identification));
	printf("\tFlags: 0x%02X (%s) \n", flags, flags & IPv4_Fragment_Flags::DontFragment ? "Don't fragment" : flags & IPv4_Fragment_Flags::MoreFragment ? "More fragment" : "Unknow");
	printf("\tFragment offset: %d\n", get_ipv4_fragment_offset(header));
	printf("\tTime to line: %d\n", header->TTL);
	printf("\tProtocol: %s (%d)\n", get_ipv4_protocol_char(header), header->Protocol);
	printf("\tHeader checksum: 0x%02X [%s]\n", htons(header->Checksum), checksum_ipv4_header(header) ? "Good: True" : "Bad: True");
	checksum_ipv4_header(header);
}
