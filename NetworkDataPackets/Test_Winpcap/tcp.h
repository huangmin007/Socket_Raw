/*************************************************************
*
*	������Э����Ĳ� ����� TCP �ṹ����
*	�ο���https://zh.wikipedia.org/wiki/%E4%BC%A0%E8%BE%93%E6%8E%A7%E5%88%B6%E5%8D%8F%E8%AE%AE
*
*	�ߵ��ֽ���ת����htonl��ntohl��htons��ntohs������
*	htons ��uint16_t���ʹ�������ת����������
*	htonl ��uint32_t���ʹ�������ת����������
*	ntohs ��uint16_t���ʹ�������ת����������
*	ntohl ��uint32_t���ʹ�������ת����������
*/
#pragma once

#include <stdio.h>
#include <stdint.h>
#include <winsock.h>

/*
	����� TCP �ṹ����
*/
typedef struct tcp_header
{
	//Դ�˿ں��ֶΡ�ռ16���أ�TCPЭ��ͨ��ʹ��"�˿�"����ʶԴ�˺�Ŀ��˵�Ӧ�ý��̡�
	//�˿ںſ���ʹ��0��65535֮����κ����֡����յ���������ʱ������ϵͳ��̬��Ϊ�ͻ��˵�Ӧ�ó������˿ںš�
	//�ڷ������ˣ�ÿ�ַ�����"������֪�Ķ˿�"��Well-Know Port��Ϊ�û��ṩ����
	uint16_t	SrcPort;

	//Ŀ��˿ں��ֶΡ�ռ16���أ�TCPЭ��ͨ��ʹ��"�˿�"����ʶԴ�˺�Ŀ��˵�Ӧ�ý��̡�
	//�˿ںſ���ʹ��0��65535֮����κ����֡����յ���������ʱ������ϵͳ��̬��Ϊ�ͻ��˵�Ӧ�ó������˿ںš�
	//�ڷ������ˣ�ÿ�ַ�����"������֪�Ķ˿�"��Well-Know Port��Ϊ�û��ṩ����
	uint16_t	DstPort;

	//˳����ֶΡ�ռ32���أ�������ʶ��TCPԴ����TCPĿ��˷��͵������ֽ���������ʾ��������Ķ��еĵ�һ�������ֽڡ�
	uint32_t	SequenceNumber;

	//ȷ�Ϻ��ֶΡ�ռ32���أ�ֻ��ACK��־Ϊ1ʱ��ȷ�Ϻ��ֶβ���Ч��������Ŀ����������յ�Դ�˵���һ�������ֽڡ�
	uint32_t	AcknowledgmentNumber;

	//����ƫ�����־λ��
	//����ƫ��/ͷ�������ֶΣ�ռ��4λ
	//�����м�3λ
	//��־����ռ9��λ
	uint16_t	DataOffsetAndFlag;

	//���ڴ�С�ֶΡ�ռ16���أ����ֶ����������������ơ���λΪ�ֽ��������ֵ�Ǳ�������һ�ν��յ��ֽ�����
	uint16_t	Window;

	//TCPУ����ֶΡ�ռ16���أ�������TCP���ĶΣ���TCPͷ����TCP���ݽ���У��ͼ��㣬����Ŀ��˽�����֤��
	uint16_t	Checksum;
	//����ָ���ֶΡ�ռ16���أ�����һ��ƫ������������ֶ��е�ֵ��ӱ�ʾ�����������һ���ֽڵ���š�
	uint16_t	UrgentPointer;

	//ѡ���ֶΡ�ռ32���أ����ܰ���"������������"��"ʱ���"��ѡ�
	//uint16_t Options;
} TCP_Header;

/*
	TCP�ṹ��־��Ϣ��λ�ڱ�־�� DataOffsetAndFlag ��9λ
*/
typedef enum tcp_flags
{
	Fin = 0x0001,		//Ϊ1��ʾ���ͷ�û������Ҫ�����ˣ�Ҫ���ͷ�����
	Syn = 0x0002,		//Ϊ1��ʾ������������������ӽ����������ڴ������Ӻ�ʹ˳���ͬ��
	Reset = 0x0004,		//Ϊ1��ʾ�������ز��������Ҫ���ִ���TCP���ӡ����������ھܾ��Ƿ��ı��Ķκ;ܾ���������
	Push = 0x0008,		//Ϊ1��ʾ�Ǵ���PUSH��־�����ݣ�ָʾ���շ�Ӧ�þ��콫������Ķν���Ӧ�ò�����õȴ�������װ��
	Acknow = 0x0010,	//Ϊ1��ʾȷ�Ϻ��ֶ� Acknowledgement ��Ч
	Urgent = 0x0020,	//Ϊ1��ʾ�����ȼ����ݰ�������ָ���ֶ� urgent pointer ��Ч
	ECNEcho = 0x0040,	//Echo��������˼��ȡ����SYN��־��ֵ
	CWR = 0x0080,		//Congestion Window Reduced
	Nonce = 0x0100,		//NS��ECN
						//Reserved = 0xE000,	//����
}TCP_Flags;


/*

	��������	:	��ȡ TCP �ṹ���ݳ��ȣ�����Э�� TCP �ṹ������һ���ɱ䳤�ȵĽṹ��λ�ڽṹ�ֶ� DataOffsetAndFlag �У���4λ�����ֵ0x0F * 4 = 60�����60�ֽ�
	�������	:	const TCP_Header *header
	�������	:	��
	�� �� ֵ	:	���� TCP �ṹ���ݳ���

*/
static uint8_t get_tcp_length(const TCP_Header *header)
{
	return ((htons(header->DataOffsetAndFlag) & 0xF000) >> 12) * 4;
}

/*

��������	:	��ȡ TCP �ṹ��־��Ϣ��λ�ڽṹ�ֶ� DataOffsetAndFlag �У���9λ
�������	:	const TCP_Header *header
�������	:	��
�� �� ֵ	:	���� TCP ��־��Ϣ���ο���tcp_flags

*/
static uint16_t get_tcp_flags(const TCP_Header *header)
{
	return htons(header->DataOffsetAndFlag) & 0x01FF;
}

/*

	��������	:	��ȡ TCP �ṹ��־�ַ�����ʽ
	�������	:	uint16_t flags�� �ο���tcp_flags
	�������	:	char *flags_char  ����ַ���
	�� �� ֵ	:	���� ��־�ַ�����ʽ��ʾ��Fin, Syn

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

	��������	:	��ȡ TCP �ṹ����У���
	�������	:	const TCP_Header *header
	�������	:	��
	�� �� ֵ	:	���� ����У������ȷ���

*/
static bool checksum_tcp_header(const TCP_Header *header, const uint8_t *data)
{
	printf("checksum_tcp_header(*TCP_Header, *uint8_t) δʵ��... \n");
	return 0;
}

/*

	��������	:	��ȡ TCP �ṹ��־�ַ�����ʽ
	�������	:	const TCP_Header *header
	�������	:	��
	�� �� ֵ	:	���� ��־�ַ�����ʽ

*/
static char* get_tcp_flags_char(const TCP_Header *header)
{
	static char flags[32];	
	memset(flags, 0x00, 32);
	return get_tcp_flags_char(get_tcp_flags(header), flags);
}


/*

��������	:	������� TCP �ṹ����ԭʼ�ֽ�����
�������	:	const TCP_Header *header
�������	:	��
�� �� ֵ	:	��

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

��������	:	������� TCP �ṹ������Ϣ
�������	:	const TCP_Header *header
�������	:	��
�� �� ֵ	:	��

*/
static void print_tcp_info(const TCP_Header *header)
{
	printf("+Transmission Control Protocol, Src Port: %d  Dst Port: %d  Seq: %d  Ack: %d\n", ntohs(header->SrcPort), ntohs(header->DstPort), htonl(header->SequenceNumber), htonl(header->AcknowledgmentNumber));
	printf("\tHeader length: %d bytes\n", get_tcp_length(header));
	printf("\tFlags: 0x%2X (%s) \n", get_tcp_flags(header), get_tcp_flags_char(header));
	printf("\tWindow size: 0x%02X (%d) \n", htons(header->Window), htons(header->Window));
	printf("\tChecksum: 0x%02X [%s]\n", htons(header->Checksum), "validation disabled(��֤����)");

}