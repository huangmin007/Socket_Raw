
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
//#include <WinSock2.h>
#include <winsock.h>
#include <windows.h>

#include "net_protocol_header.h"

#pragma comment( lib, "ws2_32.lib" ) 

#define IP_HDRINCL 2
#define BUFFER_SIZE 0xFFFF
#define SIO_RCVALL 0x98000001




int main(int argc, char *argv[])
{
	printf("test\n");

	WSADATA WSAData;
	//���Winsock�汾��
	if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0)
	{
		printf("Version Error.\n");
		system("pause");
		return -1;
	}

	SOCKET sock;
	// ��ʼ�� Raw Socket	IPPROTO_RAW/
	//AF_INET PF_PACKET
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == INVALID_SOCKET)
	{
		printf("Create Socket Failed.\n");
		system("pause");
		return -1;
	}
	
	BOOL flag = true;
	// ����IPͷ����ѡ��
	//IPPROTO_TP˵���û��Լ���дIP����
	//IP_HDRINCL��ʾ���ں�������IP���ĵ�ͷ��У��ͣ�������Ǹ�IP��id 
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag)) == SOCKET_ERROR)
	{
		printf("Set Socket option error.\n");
		system("pause");
		return -1;
	}
	

	char LocalName[16];
	// ��ȡ������
	if (gethostname((char*)LocalName, 16) == SOCKET_ERROR)
	{
		printf("Get Host Name Error.\n");
	}
	printf("Host Name: %s\n", LocalName);

	hostent *pHost;
	// ��ȡ���� IP ��ַ
	if ((pHost = gethostbyname((char*)LocalName)) == NULL)
	{
		printf("Get Host Address Error.\n");
	}
	printf("Host Address: %s\n", pHost->h_addr_list[0]);

	struct sockaddr_in addr_in;
	addr_in.sin_addr = *(in_addr *)pHost->h_addr_list[0]; //IP
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(52000);						//Port
	
	// sock �󶨵����ص�ַ��
	if (bind(sock, (struct sockaddr*)&addr_in, sizeof(addr_in)) == SOCKET_ERROR)
	{
		printf("Sock bind Error.\n");
		system("pause");
		return -1;
	}


	DWORD dwValue = 1;
	// ���� SOCK_RAW ΪSIO_RCVALL���Ա�������е�IP��
	if (ioctlsocket(sock, SIO_RCVALL, &dwValue) != 0)
	{
		printf("ioctl socket error.\n");
		system("pause");
		return -1;
	}

	int ret;
	ipv4_header    ip_h;
	tcp_header   tcp_h;
	char RecvBuf[BUFFER_SIZE];
	while (1)
	{
		//ret = recv(sock, RecvBuf, BUFFER_SIZE, 0);
		ret = recvfrom(sock, RecvBuf, BUFFER_SIZE, 0, NULL, NULL);
		if (ret == SOCKET_ERROR)
		{
			continue;
		}
		else if (!ret)
		{
			printf("network error.\n");
			system("pause");
			return -1;
		}
		if (ret < 0)
			continue;

		//printf("len:%d\n", ret);
		//continue;

		ip_h = *(ipv4_header *)RecvBuf;
		print_ipv4_raw(&ip_h);
		print_ipv4_info(&ip_h);
		
		if (ip_h.Protocol != IPPROTO_TCP)
		{
			printf("\n");
			memset(RecvBuf, 0x00, BUFFER_SIZE);
			continue;
		}


		tcp_h = *(tcp_header *)(RecvBuf + sizeof(ip_h));
		print_tcp_raw(&tcp_h);
		print_tcp_info(&tcp_h);
		//printf("TCP_HEADER: HeaderLength:%d  Source:%d  Destination:%d  Seq:%lu  Ack:%lu \n", ((ntohs(tcp_h.DataOffsetAndFlag) & 0xF000) >> 12) * 32 / 8, ntohs(tcp_h.SrcPort), ntohs(tcp_h.DstPort), htons(tcp_h.SequenceNumber), htons(tcp_h.AcknowledgmentNumber));
		
		int ipHeaderLength = get_ipv4_length(&ip_h);
		int tcpHeaderLength = get_tcp_length(&tcp_h);
		int dataLength = htons(ip_h.TotalLength) - ipHeaderLength - tcpHeaderLength;

		if (dataLength == 0)
		{
			printf("\n");
			memset(RecvBuf, 0x00, BUFFER_SIZE);
			continue;
		}


		byte *data = (byte*)malloc(dataLength);
		memset(data, 0x00, dataLength);
		//char *data = (char*)(RecvBuf + ipHeaderLength + tcpHeaderLength);
		memcpy(data, (void *)(RecvBuf + ipHeaderLength + tcpHeaderLength), dataLength);
		printf("Data: Length: %d  %s\n\n", dataLength, data);
		free(data);

		memset(RecvBuf, 0x00, BUFFER_SIZE);
	}

	closesocket(sock);

	system("pause");
	return 0;
}