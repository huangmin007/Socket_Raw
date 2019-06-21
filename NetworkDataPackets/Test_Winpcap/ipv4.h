/*************************************************************
*
*	������Э������� ����� IPv4 �ṹ����
*	�ο���https://zh.wikipedia.org/wiki/IPv4
*
*	�ߵ��ֽ���ת����htonl��ntohl��htons��ntohs������
*	htons ��uint16_t���ʹ�������ת����������
*	htonl ��uint32_t���ʹ�������ת����������
*	ntohs ��uint16_t���ʹ�������ת����������
*	ntohl ��uint32_t���ʹ�������ת����������
*
*/

#pragma once
#include <stdio.h>
#include <stdint.h>
#include <winsock.h>


/*
	����� IPv4 �ṹ����
*/
typedef struct ipv4_header
{
	//�汾��Ϣ(ǰ4λ)����ͷ����(��4λ)
	//Version���汾����ռ4���أ���������IPЭ��ʵ�ֵİ汾�ţ���ǰһ��ΪIPv4����0100��
	//Internet Header Length(IHL)����ͷ���ȣ���ռ4���أ���ʾͷ��ռ32���صĳ����Ƕ��٣�����˵�������κ�ѡ���IP���ݱ����� Destination AddressΪֹ��32x5=160����=20�ֽڣ����ֶ����ֵΪ60�ֽڡ�
	uint8_t		VersionAndHeaderLen;

	//���ַ���Differentiated Services��DS����ռ6bit�����������Ϊ���������ֶΣ�ʵ���ϲ�δʹ�ã���1998�걻IETF�ض���Ϊ���ַ���RFC 2474��ֻ����ʹ�����ַ���ʱ������ֶβ������ã���һ������  �¶���ʹ������ֶΡ�������Ҫʵʱ�������ļ�����Ӧ������ֶΣ�һ��������VoIP��
	//��ʽӵ��ͨ�棨 Explicit Congestion Notification��ECN����ռ��2λ
	uint8_t		DSAndECN;

	//�ܳ����ֶΡ�ռ16���أ�ָ���������ݱ��ĳ��ȣ����ֽ�Ϊ��λ������󳤶�Ϊ65535�ֽڡ�
	uint16_t	TotalLength;

	//��ʶ��ռ16���أ�����Ψһ�ر�ʶ�������͵�ÿһ�����ݱ���ͨ��ÿ��һ�ݱ��ģ�����ֵ���1��
	uint16_t	Identification;

	//��־λ��Ƭ��ƫ�ơ�
	//Flags��־ռ3���أ���ʾ��ݱ����Ƿ���Ҫ��Ƭ���䡣
	//Fragment Offset
	uint16_t	FlagsAndFragment;

	//Time to live(TTL)�����ڡ�ռ8���أ�������ʾ�����ݱ��������Ծ�����·��������û����һ��·��������1��ֱ��Ϊ0���ݰ�������
	uint8_t		TTL;

	//���Ĳ㴫���Э���ֶΡ�ռ8���أ�����ָ��IP������װ���ϲ�Э�����ͣ��紫���TCP/UDP/ICMP/IGMP�ȡ�
	uint8_t		Protocol;

	//ͷ��У����ֶΡ�ռ16���أ������Ǹ���IPͷ������õ���У����롣
	//���㷽���ǣ���ͷ����ÿ��16���ؽ��ж����Ʒ�����͡�����ICMP��IGMP��TCP��UDP��ͬ��IP����ͷ��������ݽ���У�飩��
	uint16_t	Checksum;

	//Դ��ַ.ռ32�ֽڣ����IPV4
	uint32_t	SrcAddr;

	//Ŀ�ĵ�ַ��ռ32�ֽڣ����IPV4
	uint32_t	DstAddr;

	//��ѡ���ֶΡ�ռ32���أ���������һЩ��ѡ����¼·����ʱ����ȡ���Щѡ����ٱ�ʹ�ã�ͬʱ����������������·������֧����Щѡ�
	//��ѡ���ֶεĳ��ȱ�����32���ص���������������㣬�������0�Դﵽ�˳���Ҫ��
	//uint32_t	Options;		
} IPv4_Header;

/*
	IP��������
*/
typedef enum ipv4_type_of_service
{
	ECN_CE = 0x01,		//ECN-CE

	ECN_CT = 0x02,		//ECN-Capable Transport(ECT)

}IPv4_Type_Of_Service;

/*
	IPv4�ṹ��Ƭ��־��Ϣ��ռ3λ�ֶ����ڿ��ƺ�ʶ���Ƭ
*/
typedef enum ipv4_fragment_flags
{
	//�����Ƭ��More Fragment��MF����MF=1������滹�з�Ƭ��MF=0 �����Ѿ������һ����Ƭ��
	MoreFragment = 0x01,

	//��ֹ��Ƭ��Don��t Fragment��DF������DF=0ʱ�������Ƭ
	DontFragment = 0x02,

	//����������Ϊ0
	//Reserved = 0x04,
	
}IPv4_Fragment_Flags;


/*

	��������	:	��ȡ IPv4 �汾��λ�ڽṹ�ֶ� VersionAndHeaderLen �У���4λ
	�������	:	const IPv4_Header *header
	�������	:	��
	�� �� ֵ	:	���� IPv4 �İ汾��

*/
static uint8_t get_ipv4_version(const IPv4_Header *header)
{
	return (header->VersionAndHeaderLen & 0xF0) >> 4;
}

/*

	��������	:	��ȡ IPv4 �ṹ���ݳ��ȣ�����Э�� IPv4 �ṹ������һ���ɱ䳤�ȵĽṹ��λ�ڽṹ�ֶ� VersionAndHeaderLen �У���4λ�����ֵ0x0F * 4 = 60�����60�ֽ�
	�������	:	const IPv4_Header *header
	�������	:	��
	�� �� ֵ	:	���� IPv4 �ṹ���ݳ���

*/
static uint8_t get_ipv4_length(const IPv4_Header *header)
{
	return (header->VersionAndHeaderLen & 0x0F) * 4;
}


/*

	��������	:	��ȡ IPv4 �ṹ�з�Ƭ��־λ��λ�ڽṹ�ֶ� FlagsAndFragment �У���3λ
	�������	:	const IPv4_Header *header
	�������	:	��
	�� �� ֵ	:	���� IPv4 ��Ƭ��־ֵ���ο���IPv4_Fragment_Flags

*/
static uint8_t get_ipv4_fragment_flags(const IPv4_Header *header)
{
	return (htons(header->FlagsAndFragment) & 0xE000) >> 13;
}


/*

	��������	:	��ȡ IPv4 �ṹ�� Fragment Offset ��Ϣ��λ�ڽṹ�ֶ� FlagsAndFragment �У���13λ
	�������	:	const IPv4_Header *header
	�������	:	��
	�� �� ֵ	:	���� Fragment Offset ֵ

*/
static uint16_t get_ipv4_fragment_offset(const IPv4_Header *header)
{
	return htons(header->FlagsAndFragment) & 0x1FFF;
}

/*

	��������	:	��ȡ IPv4 �ṹ�� �����Э���ַ���
	�������	:	int value Э��ֵ���ο���winsock.h Protocols
	�������	:	��
	�� �� ֵ	:	���� IPv4 �����Э���ַ�����ʽ

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

	��������	:	��ȡ IPv4 �ṹ�� �����Э���ַ���
	�������	:	const IPv4_Header *header
	�������	:	��
	�� �� ֵ	:	���� IPv4 �����Э���ַ�����ʽ

*/
static char* get_ipv4_protocol_char(const IPv4_Header *header)
{
	return get_ipv4_protocol_char(header->Protocol);
}

/*

	��������	:	��ȡ IPv4 �ṹ����У���
	�������	:	const IPv4_Header *header
	�������	:	��
	�� �� ֵ	:	���� ����У������ȷ���

*/
static bool checksum_ipv4_header(const IPv4_Header *header)
{
	uint8_t size = sizeof(IPv4_Header);
	uint8_t *raw = (uint8_t*)header;
	//uint8_t *raw = (uint8_t*)malloc(size);	
	//memcpy(raw, header, sizeof(IPv4_Header));

	uint32_t sum = 0;

	for (uint8_t i = 0; i < size; i+=2)
		sum += (raw[i] << 8) | raw[i + 1];		//ÿ16bit���������
	
	sum -= htons(header->Checksum);				//����ԭУ��ֵ������Ľ������ԭ����ֵ�����������������Ϊ0����������ȷ
	
	sum = (sum >> 16) + (sum & 0xFFFF);			//��16bit�͵�16bit��ӣ�ֱ����16λΪ0
	sum += (sum >> 16);							//ֱ����16λΪ0

	//free(raw);
	//printf("check sum: 0x%02X \n", (uint16_t)(~sum));

	return (uint16_t)(~sum) == htons(header->Checksum);
}

/*

	��������	:	��ȡ IPv4 ip��ַ
	�������	:	uint32_t value �� С�˸�ʽ ��->��
	�������	:	char *addr ���ip��ַ���ַ�����ʽ��addr���Ȳ���С��16
	�� �� ֵ	:	���� ip��ַ���ַ�����ʽ

*/
static char* get_ipv4_address(uint32_t value, char *addr)
{
	sprintf_s(addr, 16, "%d.%d.%d.%d", (value & 0xFF000000) >> 24, (value & 0x00FF0000) >> 16, (value & 0x0000FF00) >> 8, value & 0xFF);
	return addr;
}

/*

	��������	:	��ȡ IPv4 �ṹ������Դip��ַ���ַ�����ʽ
	�������	:	uint32_t value �� С�˸�ʽ ��->��
	�������	:	��
	�� �� ֵ	:	���� ip��ַ���ַ�����ʽ

*/
static char* get_ipv4_src_address(const IPv4_Header *header)
{
	static char src[16];
	memset(src, 0x00, 16);
	return get_ipv4_address(htonl(header->SrcAddr), src);
	//return src;
}

/*

	��������	:	��ȡ IPv4 �ṹ������Ŀ��ip��ַ���ַ�����ʽ
	�������	:	uint32_t value �� С�˸�ʽ ��->��
	�������	:	��
	�� �� ֵ	:	���� ip��ַ���ַ�����ʽ

*/
static char* get_ipv4_dst_address(const IPv4_Header *header)
{
	static char dst[16];
	memset(dst, 0x00, 16);
	return get_ipv4_address(htonl(header->DstAddr), dst);
	//return dst;
}

/*

��������	:	������� IPv4 �ṹ����ԭʼ�ֽ�����
�������	:	const IPv4_Header *header
�������	:	��
�� �� ֵ	:	��

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

	��������	:	������� IPv4 �ṹ������Ϣ
	�������	:	const IPv4_Header *header
	�������	:	��
	�� �� ֵ	:	��

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
