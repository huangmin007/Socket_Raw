/*************************************************************
*
*	互联网协议第四层 传输层 TCP 结构数据
*	参考：https://zh.wikipedia.org/wiki/%E4%BC%A0%E8%BE%93%E6%8E%A7%E5%88%B6%E5%8D%8F%E8%AE%AE
*
*	高低字节序转换（htonl、ntohl、htons、ntohs函数）
*	htons 把uint16_t类型从主机序转换到网络序
*	htonl 把uint32_t类型从主机序转换到网络序
*	ntohs 把uint16_t类型从网络序转换到主机序
*	ntohl 把uint32_t类型从网络序转换到主机序
*/
#pragma once

#include <stdio.h>
#include <stdint.h>
#include <winsock.h>

/*
	传输层 TCP 结构数据
*/
typedef struct tcp_header
{
	//源端口号字段。占16比特，TCP协议通过使用"端口"来标识源端和目标端的应用进程。
	//端口号可以使用0到65535之间的任何数字。在收到服务请求时，操作系统动态地为客户端的应用程序分配端口号。
	//在服务器端，每种服务在"众所周知的端口"（Well-Know Port）为用户提供服务。
	uint16_t	SrcPort;

	//目标端口号字段。占16比特，TCP协议通过使用"端口"来标识源端和目标端的应用进程。
	//端口号可以使用0到65535之间的任何数字。在收到服务请求时，操作系统动态地为客户端的应用程序分配端口号。
	//在服务器端，每种服务在"众所周知的端口"（Well-Know Port）为用户提供服务。
	uint16_t	DstPort;

	//顺序号字段。占32比特，用来标识从TCP源端向TCP目标端发送的数据字节流，它表示在这个报文段中的第一个数据字节。
	uint32_t	SequenceNumber;

	//确认号字段。占32比特，只有ACK标志为1时，确认号字段才有效。它包含目标端所期望收到源端的下一个数据字节。
	uint32_t	AcknowledgmentNumber;

	//数据偏移与标志位。
	//数据偏移/头部长度字段，占高4位
	//保留中间3位
	//标志符，占9个位
	uint16_t	DataOffsetAndFlag;

	//窗口大小字段。占16比特，此字段用来进行流量控制。单位为字节数，这个值是本机期望一次接收的字节数。
	uint16_t	Window;

	//TCP校验和字段。占16比特，对整个TCP报文段，即TCP头部和TCP数据进行校验和计算，并由目标端进行验证。
	uint16_t	Checksum;
	//紧急指针字段。占16比特，它是一个偏移量，和序号字段中的值相加表示紧急数据最后一个字节的序号。
	uint16_t	UrgentPointer;

	//选项字段。占32比特，可能包括"窗口扩大因子"、"时间戳"等选项。
	//uint16_t Options;
} TCP_Header;

/*
	TCP结构标志信息，位于标志段 DataOffsetAndFlag 低9位
*/
typedef enum tcp_flags
{
	Fin = 0x0001,		//为1表示发送方没有数据要传输了，要求释放连接
	Syn = 0x0002,		//为1表示这是连接请求或是连接接受请求，用于创建连接和使顺序号同步
	Reset = 0x0004,		//为1表示出现严重差错。可能需要重现创建TCP连接。还可以用于拒绝非法的报文段和拒绝连接请求
	Push = 0x0008,		//为1表示是带有PUSH标志的数据，指示接收方应该尽快将这个报文段交给应用层而不用等待缓冲区装满
	Acknow = 0x0010,	//为1表示确认号字段 Acknowledgement 有效
	Urgent = 0x0020,	//为1表示高优先级数据包，紧急指针字段 urgent pointer 有效
	ECNEcho = 0x0040,	//Echo有两种意思，取决于SYN标志的值
	CWR = 0x0080,		//Congestion Window Reduced
	Nonce = 0x0100,		//NS—ECN
						//Reserved = 0xE000,	//保留
}TCP_Flags;


/*

	功能描述	:	获取 TCP 结构数据长度，跟据协议 TCP 结构数据是一个可变长度的结构。位于结构字段 DataOffsetAndFlag 中，高4位，最大值0x0F * 4 = 60，最大60字节
	输入参数	:	const TCP_Header *header
	输出参数	:	无
	返 回 值	:	返回 TCP 结构数据长度

*/
static uint8_t get_tcp_length(const TCP_Header *header)
{
	return ((htons(header->DataOffsetAndFlag) & 0xF000) >> 12) * 4;
}

/*

功能描述	:	获取 TCP 结构标志信息。位于结构字段 DataOffsetAndFlag 中，低9位
输入参数	:	const TCP_Header *header
输出参数	:	无
返 回 值	:	返回 TCP 标志信息，参考：tcp_flags

*/
static uint16_t get_tcp_flags(const TCP_Header *header)
{
	return htons(header->DataOffsetAndFlag) & 0x01FF;
}

/*

	功能描述	:	获取 TCP 结构标志字符串形式
	输入参数	:	uint16_t flags， 参考：tcp_flags
	输出参数	:	char *flags_char  输出字符串
	返 回 值	:	返回 标志字符串形式，示例Fin, Syn

*/
static char* get_tcp_flags_char(uint16_t flags, char *flags_char)
{
	char *tcp_flags[9] = { "Fin", "Syn", "Reset", "Push", "Acknow", "Urgent", "ECN-Echo", "CWR", "Nonce"};
	
	uint8_t len;
	uint8_t offset = 0;
	char decollator[3] = ", ";

	for (uint8_t i = 0; i < 9; i++)
	{
		if ((flags >> i) & 0x01)
		{
			len = strlen(tcp_flags[i]);	
			if (offset != 0)
			{
				memcpy(flags_char + offset, decollator, 2);	offset += 2;				
				memcpy(flags_char + offset, tcp_flags[i], len); offset += len;
			}
			else
			{
				memcpy(flags_char + offset, tcp_flags[i], len); offset += len;
			}
		}
	}

	return flags_char;
}

/*

	功能描述	:	获取 TCP 结构数据校验和
	输入参数	:	const TCP_Header *header
	输出参数	:	无
	返 回 值	:	返回 数据校验结果正确与否

*/
static bool checksum_tcp_header(const TCP_Header *header, const uint8_t *data)
{
	printf("checksum_tcp_header(*TCP_Header, *uint8_t) 未实现... \n");
	return 0;
}

/*

	功能描述	:	获取 TCP 结构标志字符串形式
	输入参数	:	const TCP_Header *header
	输出参数	:	无
	返 回 值	:	返回 标志字符串形式

*/
static char* get_tcp_flags_char(const TCP_Header *header)
{
	static char flags[32];	
	memset(flags, 0x00, 32);
	return get_tcp_flags_char(get_tcp_flags(header), flags);
}


/*

功能描述	:	测试输出 TCP 结构数据原始字节数据
输入参数	:	const TCP_Header *header
输出参数	:	无
返 回 值	:	无

*/
static void print_tcp_raw(const TCP_Header *header)
{
	uint8_t size = sizeof(TCP_Header);
	uint8_t *buffer = (uint8_t*)malloc(size);
	memcpy(buffer, header, size);

	for (int i = 0; i < size; i++)
		printf("%02X ", buffer[i]);
	printf("\n");

	free(buffer);
}

/*

功能描述	:	测试输出 TCP 结构数据信息
输入参数	:	const TCP_Header *header
输出参数	:	无
返 回 值	:	无

*/
static void print_tcp_info(const TCP_Header *header)
{
	printf("+Transmission Control Protocol, Src Port: %d  Dst Port: %d  Seq: %d  Ack: %d\n", ntohs(header->SrcPort), ntohs(header->DstPort), htonl(header->SequenceNumber), htonl(header->AcknowledgmentNumber));
	printf("\tHeader length: %d bytes\n", get_tcp_length(header));
	printf("\tFlags: 0x%2X (%s) \n", get_tcp_flags(header), get_tcp_flags_char(header));
	printf("\tWindow size: 0x%02X (%d) \n", htons(header->Window), htons(header->Window));
	printf("\tChecksum: 0x%02X [%s]\n", htons(header->Checksum), "validation disabled(验证禁用)");

}