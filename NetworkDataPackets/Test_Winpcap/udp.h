/*************************************************************
*
*	互联网协议第四层 传输层 TCP 结构数据
*	参考：
*
*/
#pragma once
#include <stdio.h>
#include <stdint.h>

//UDP头部信息
struct udp_header
{
	uint16_t SrcPort;		// 源端口号16bit
	uint16_t DstPort;		// 目的端口号16bit
	uint16_t Length;		// 数据包长度16bit
	uint16_t Checksum;		// 校验和16bit
}UDP_Header;

static bool checksum_udp_header(const udp_header *header, const uint8_t *data)
{
	return 0;
}