/*************************************************************
*
*	������Э����Ĳ� ����� TCP �ṹ����
*	�ο���
*
*/
#pragma once
#include <stdio.h>
#include <stdint.h>

//UDPͷ����Ϣ
struct udp_header
{
	uint16_t SrcPort;		// Դ�˿ں�16bit
	uint16_t DstPort;		// Ŀ�Ķ˿ں�16bit
	uint16_t Length;		// ���ݰ�����16bit
	uint16_t Checksum;		// У���16bit
}UDP_Header;

static bool checksum_udp_header(const udp_header *header, const uint8_t *data)
{
	return 0;
}