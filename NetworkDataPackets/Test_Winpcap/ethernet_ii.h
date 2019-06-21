/*************************************************************
 *
 *	互联网协议第二层 链路层 Ethernet II 结构数据
 *	参考：https://zh.wikipedia.org/wiki/%E4%BB%A5%E5%A4%AA%E7%BD%91
 *
 */
#pragma once

#include <stdio.h>
#include <stdint.h>

#define		MAC_ADDRESS_LENGTH		6		//mac地址长度

/*
	链路层 Ethernet II 结构数据
*/
typedef struct ethernet_ii_header
{
	//目地Mac地址。占6个字节
	uint8_t DstMacAddress[6];

	//源Mac地址。占6个字节
	uint8_t SrcMacAddress[6];

	//网络层(第三层)协议类型
	uint16_t Type;

}Ethernet_II_Header;


/*
	
	以太网网络层(第三层)协议类型

*/
typedef enum ethernet_ii_type
{
	IPv4 = 0x0800,			//IPv4 协议

	ARP = 0x0806,			//ARP 协议

	RARP = 0x8035,			//RARP 协议

	IEEE_802_1_Q = 0x8100,	//IEEE 802.1 Q

	IPv6 = 0x86DD,			//IPv6 协议

	PPP = 0x880B,			//PPP 协议

	PPPOE_Dis = 0x8863,		//PPPOE Discovery

	PPPOE_Ses = 0x8864,		//PPPOE Session

	//...还有需要查资料，这时已经不重要了

}Ethernet_II_Type;

/*

	功能描述	:	将6字节长的 uint8_t 类型转为 mac 类型字符
	输入参数	:	uint8_t *addr  长度为6的uint8_t数组
					char delimiter	mac地址格式的分割符，一般使用"-"或":"
	输出参数	:	无
	返 回 值	:	返回mac地址的字符串形式

*/
static char* get_convert_mac_addr(const uint8_t addr[6], char delimiter = '-')
{
	char mac[18];
	sprintf_s(mac, "%02X%s%02X%s%02X%s%02X%s%02X%s%02X%s", addr[0], delimiter, addr[1], delimiter, addr[2], delimiter, addr[3], delimiter, addr[4], delimiter, addr[5]);
	return mac;
}

/*
	
	功能描述	:	获取以太目标mac地址
	输入参数	:	const Ethernet_II_Header *header
	输出参数	:	无
	返 回 值	:	返回mac地址的字符串形式

*/
static char* get_ethernet_dst_addr(const Ethernet_II_Header *header)
{
	return get_convert_mac_addr(header->DstMacAddress, '-');
}

/*

	功能描述	:	获取以太源mac地址
	输入参数	:	const Ethernet_II_Header *header
	输出参数	:	无
	返 回 值	:	返回mac地址的字符串形式

*/
static char* get_ethernet_src_addr(const Ethernet_II_Header *header)
{
	return get_convert_mac_addr(header->SrcMacAddress, '-');
}


/*

	功能描述	:	获取以太结构中的网络层(第三层)协议类型字符
	输入参数	:	uint16_t type  协议类型值，参考 : enum Ethernet_II_Type
	输出参数	:	无
	返 回 值	:	返回网线程层协议类型的字符串形式

*/
static char* get_ethernet_type_char(uint16_t type)
{
	switch (type)
	{
	case Ethernet_II_Type::IPv4:	return "IPv4";
	case Ethernet_II_Type::IPv6:	return "IPv6";
	case Ethernet_II_Type::ARP:		return "ARP";
	case Ethernet_II_Type::IEEE_802_1_Q:		return "IEEE 802.1 Q";
	}
	return "Unknow";
}


/*

	功能描述	:	获取以太结构中的网络层(第三层)协议类型字符
	输入参数	:	const Ethernet_II_Header *header
	输出参数	:	无
	返 回 值	:	返回网线程层协议类型的字符串形式

*/
static char* get_ethernet_type_char(const Ethernet_II_Header *header)
{
	return get_ethernet_type_char(header->Type);
}


/*

功能描述	:	测试输出 Ethernet_II 结构数据原始字节数据
输入参数	:	const Ethernet_II *header
输出参数	:	无
返 回 值	:	无

*/
static void print_ethernet_raw(const Ethernet_II_Header *header)
{
	uint8_t size = sizeof(Ethernet_II_Header);
	uint8_t *buffer = (uint8_t*)malloc(size);
	memcpy(buffer, header, size);

	for (int i = 0; i < size; i++)
		printf("%02X ", buffer[i]);
	printf("\n");

	free(buffer);
}


/*

	功能描述	:	测试输出 Ethernet_II 结构数据
	输入参数	:	const Ethernet_II_Header *header
	输出参数	:	无
	返 回 值	:	无

*/
static void print_ethernet_info(const Ethernet_II_Header *header)
{
	printf("+Ethernet II, Source: %s, Destination: %s, Type: %s (0x%02X)\n", get_ethernet_src_addr(header), get_ethernet_dst_addr(header), get_ethernet_type_char(header), header->Type);

}