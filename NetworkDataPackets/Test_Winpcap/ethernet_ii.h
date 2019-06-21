/*************************************************************
 *
 *	������Э��ڶ��� ��·�� Ethernet II �ṹ����
 *	�ο���https://zh.wikipedia.org/wiki/%E4%BB%A5%E5%A4%AA%E7%BD%91
 *
 */
#pragma once

#include <stdio.h>
#include <stdint.h>

#define		MAC_ADDRESS_LENGTH		6		//mac��ַ����

/*
	��·�� Ethernet II �ṹ����
*/
typedef struct ethernet_ii_header
{
	//Ŀ��Mac��ַ��ռ6���ֽ�
	uint8_t DstMacAddress[6];

	//ԴMac��ַ��ռ6���ֽ�
	uint8_t SrcMacAddress[6];

	//�����(������)Э������
	uint16_t Type;

}Ethernet_II_Header;


/*
	
	��̫�������(������)Э������

*/
typedef enum ethernet_ii_type
{
	IPv4 = 0x0800,			//IPv4 Э��

	ARP = 0x0806,			//ARP Э��

	RARP = 0x8035,			//RARP Э��

	IEEE_802_1_Q = 0x8100,	//IEEE 802.1 Q

	IPv6 = 0x86DD,			//IPv6 Э��

	PPP = 0x880B,			//PPP Э��

	PPPOE_Dis = 0x8863,		//PPPOE Discovery

	PPPOE_Ses = 0x8864,		//PPPOE Session

	//...������Ҫ�����ϣ���ʱ�Ѿ�����Ҫ��

}Ethernet_II_Type;

/*

	��������	:	��6�ֽڳ��� uint8_t ����תΪ mac �����ַ�
	�������	:	uint8_t *addr  ����Ϊ6��uint8_t����
					char delimiter	mac��ַ��ʽ�ķָ����һ��ʹ��"-"��":"
	�������	:	��
	�� �� ֵ	:	����mac��ַ���ַ�����ʽ

*/
static char* get_convert_mac_addr(const uint8_t addr[6], char delimiter = '-')
{
	char mac[18];
	sprintf_s(mac, "%02X%s%02X%s%02X%s%02X%s%02X%s%02X%s", addr[0], delimiter, addr[1], delimiter, addr[2], delimiter, addr[3], delimiter, addr[4], delimiter, addr[5]);
	return mac;
}

/*
	
	��������	:	��ȡ��̫Ŀ��mac��ַ
	�������	:	const Ethernet_II_Header *header
	�������	:	��
	�� �� ֵ	:	����mac��ַ���ַ�����ʽ

*/
static char* get_ethernet_dst_addr(const Ethernet_II_Header *header)
{
	return get_convert_mac_addr(header->DstMacAddress, '-');
}

/*

	��������	:	��ȡ��̫Դmac��ַ
	�������	:	const Ethernet_II_Header *header
	�������	:	��
	�� �� ֵ	:	����mac��ַ���ַ�����ʽ

*/
static char* get_ethernet_src_addr(const Ethernet_II_Header *header)
{
	return get_convert_mac_addr(header->SrcMacAddress, '-');
}


/*

	��������	:	��ȡ��̫�ṹ�е������(������)Э�������ַ�
	�������	:	uint16_t type  Э������ֵ���ο� : enum Ethernet_II_Type
	�������	:	��
	�� �� ֵ	:	�������̲߳�Э�����͵��ַ�����ʽ

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

	��������	:	��ȡ��̫�ṹ�е������(������)Э�������ַ�
	�������	:	const Ethernet_II_Header *header
	�������	:	��
	�� �� ֵ	:	�������̲߳�Э�����͵��ַ�����ʽ

*/
static char* get_ethernet_type_char(const Ethernet_II_Header *header)
{
	return get_ethernet_type_char(header->Type);
}


/*

��������	:	������� Ethernet_II �ṹ����ԭʼ�ֽ�����
�������	:	const Ethernet_II *header
�������	:	��
�� �� ֵ	:	��

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

	��������	:	������� Ethernet_II �ṹ����
	�������	:	const Ethernet_II_Header *header
	�������	:	��
	�� �� ֵ	:	��

*/
static void print_ethernet_info(const Ethernet_II_Header *header)
{
	printf("+Ethernet II, Source: %s, Destination: %s, Type: %s (0x%02X)\n", get_ethernet_src_addr(header), get_ethernet_dst_addr(header), get_ethernet_type_char(header), header->Type);

}