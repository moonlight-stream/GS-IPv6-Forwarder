#define _CRT_SECURE_NO_WARNINGS

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#pragma comment(lib, "ws2_32")
#include <WinSock2.h>
#include <Mswsock.h>
#include <Ws2ipdef.h>
#include <WS2tcpip.h>

#pragma comment(lib, "iphlpapi")
#include <Iphlpapi.h>

#pragma comment(lib, "miniupnpc.lib")
#define MINIUPNP_STATICLIB
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#include "../version.h"

#define SERVICE_NAME L"GSv6FwdSvc"

LPFN_WSARECVMSG WSARecvMsg;

bool PCPMapPort(PSOCKADDR_STORAGE localAddr, int localAddrLen, PSOCKADDR_STORAGE pcpAddr, int pcpAddrLen, int proto, int port, bool enable, bool indefinite);

static const unsigned short UDP_PORTS[] = {
	47998, 47999, 48000, 48002, 48010
};

static const unsigned short TCP_PORTS[] = {
	47984, 47989, 48010
};

typedef struct _SOCKET_TUPLE {
	SOCKET s1;
	SOCKET s2;
} SOCKET_TUPLE, *PSOCKET_TUPLE;

typedef struct _LISTENER_TUPLE {
	SOCKET listener;
	unsigned short port;
} LISTENER_TUPLE, *PLISTENER_TUPLE;

typedef struct _UDP_TUPLE {
	SOCKET ipv6Socket;
	SOCKET ipv4Socket;
	unsigned short port;
} UDP_TUPLE, *PUDP_TUPLE;

int
ForwardSocketData(SOCKET from, SOCKET to)
{
	char buffer[4096];
	int len;

	len = recv(from, buffer, sizeof(buffer), 0);
	if (len <= 0) {
		return len;
	}

	if (send(to, buffer, len, 0) != len) {
		return SOCKET_ERROR;
	}

	return len;
}

DWORD
WINAPI
TcpRelayThreadProc(LPVOID Context)
{
	PSOCKET_TUPLE tuple = (PSOCKET_TUPLE)Context;
	fd_set fds;
	int err;
	bool s1ReadShutdown = false;
	bool s2ReadShutdown = false;

	for (;;) {
		FD_ZERO(&fds);

		if (!s1ReadShutdown) {
			FD_SET(tuple->s1, &fds);
		}
		if (!s2ReadShutdown) {
			FD_SET(tuple->s2, &fds);
		}
		if (s1ReadShutdown && s2ReadShutdown) {
			// Both sides gracefully closed
			break;
		}

		err = select(0, &fds, NULL, NULL, NULL);
		if (err <= 0) {
			break;
		}
		else if (FD_ISSET(tuple->s1, &fds)) {
			err = ForwardSocketData(tuple->s1, tuple->s2);
			if (err == 0) {
				// Graceful closure from s1. Propagate to s2.
				shutdown(tuple->s2, SD_SEND);
				s1ReadShutdown = true;
			}
			else if (err < 0) {
				// Forceful closure. Tear down the whole connection.
				break;
			}
		}
		else if (FD_ISSET(tuple->s2, &fds)) {
			err = ForwardSocketData(tuple->s2, tuple->s1);
			if (err == 0) {
				// Graceful closure from s2. Propagate to s1.
				shutdown(tuple->s1, SD_SEND);
				s2ReadShutdown = true;
			}
			else if (err < 0) {
				// Forceful closure. Tear down the whole connection.
				break;
			}
		}
	}

	closesocket(tuple->s1);
	closesocket(tuple->s2);
	free(tuple);
	return 0;
}

int
FindLocalAddressBySocket(SOCKET s, PIN_ADDR targetAddress)
{
	union {
		IP_ADAPTER_ADDRESSES addresses;
		char buffer[8192];
	};
	ULONG error;
	ULONG length;
	PIP_ADAPTER_ADDRESSES currentAdapter;
	PIP_ADAPTER_UNICAST_ADDRESS currentAddress;
	SOCKADDR_IN6 localSockAddr;
	int localSockAddrLen;

	// Get local address of the accepted socket so we can find the interface
	localSockAddrLen = sizeof(localSockAddr);
	if (getsockname(s, (PSOCKADDR)&localSockAddr, &localSockAddrLen) == SOCKET_ERROR) {
		printf("getsockname() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	// Get a list of all interfaces and addresses on the system
	length = sizeof(buffer);
	error = GetAdaptersAddresses(AF_UNSPEC,
		GAA_FLAG_SKIP_ANYCAST |
		GAA_FLAG_SKIP_MULTICAST |
		GAA_FLAG_SKIP_DNS_SERVER |
		GAA_FLAG_SKIP_FRIENDLY_NAME,
		NULL,
		&addresses,
		&length);
	if (error != ERROR_SUCCESS) {
		printf("GetAdaptersAddresses() failed: %d\n", error);
		return error;
	}

	// First, find the interface that owns the incoming address
	currentAdapter = &addresses;
	while (currentAdapter != NULL) {
		// Check if this interface has the IP address we want
		currentAddress = currentAdapter->FirstUnicastAddress;
		while (currentAddress != NULL) {
			if (currentAddress->Address.lpSockaddr->sa_family == AF_INET6) {
				PSOCKADDR_IN6 ifaceAddrV6 = (PSOCKADDR_IN6)currentAddress->Address.lpSockaddr;
				if (RtlEqualMemory(&localSockAddr.sin6_addr, &ifaceAddrV6->sin6_addr, sizeof(IN6_ADDR))) {
					break;
				}
			}

			currentAddress = currentAddress->Next;
		}

		if (currentAddress != NULL) {
			// It does, bail out
			break;
		}

		currentAdapter = currentAdapter->Next;
	}

	// Check if we found the incoming interface
	if (currentAdapter == NULL) {
		// Hopefully the error is caused by transient interface reconfiguration
		printf("Unable to find incoming interface\n");
		return WSAENETDOWN;
	}

	// Now find an IPv4 address on this interface
	currentAddress = currentAdapter->FirstUnicastAddress;
	while (currentAddress != NULL) {
		if (currentAddress->Address.lpSockaddr->sa_family == AF_INET) {
			PSOCKADDR_IN ifaceAddrV4 = (PSOCKADDR_IN)currentAddress->Address.lpSockaddr;
			*targetAddress = ifaceAddrV4->sin_addr;
			return 0;
		}

		currentAddress = currentAddress->Next;
	}

	// If we get here, there was no IPv4 address on this interface.
	// This is a valid situation, for example if the IPv6 interface
	// has no IPv4 connectivity. In this case, we can preserve most
	// functionality by forwarding via localhost. WoL won't work but
	// the basic stuff will.
	printf("WARNING: No IPv4 connectivity on incoming interface\n");
	targetAddress->S_un.S_addr = htonl(INADDR_LOOPBACK);
	return 0;
}

DWORD
WINAPI
TcpListenerThreadProc(LPVOID Context)
{
	PLISTENER_TUPLE tuple = (PLISTENER_TUPLE)Context;
	SOCKET acceptedSocket, targetSocket;
	SOCKADDR_IN targetAddress;
	PSOCKET_TUPLE relayTuple;
	HANDLE thread;

	printf("TCP relay running for port %d\n", tuple->port);

	for (;;) {
		acceptedSocket = accept(tuple->listener, NULL, 0);
		if (acceptedSocket == INVALID_SOCKET) {
			printf("accept() failed: %d\n", WSAGetLastError());
			break;
		}

		targetSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (targetSocket == INVALID_SOCKET) {
			printf("socket() failed: %d\n", WSAGetLastError());
			closesocket(acceptedSocket);
			continue;
		}

		RtlZeroMemory(&targetAddress, sizeof(targetAddress));
		targetAddress.sin_family = AF_INET;
		targetAddress.sin_port = htons(tuple->port);
		if (FindLocalAddressBySocket(acceptedSocket, &targetAddress.sin_addr) != 0) {
			closesocket(acceptedSocket);
			closesocket(targetSocket);
			continue;
		}

		if (connect(targetSocket, (PSOCKADDR)&targetAddress, sizeof(targetAddress)) == SOCKET_ERROR) {
			printf("connect() failed: %d\n", WSAGetLastError());
			closesocket(acceptedSocket);
			closesocket(targetSocket);
			continue;
		}

		relayTuple = (PSOCKET_TUPLE)malloc(sizeof(*relayTuple));
		if (relayTuple == NULL) {
			closesocket(acceptedSocket);
			closesocket(targetSocket);
			break;
		}

		relayTuple->s1 = acceptedSocket;
		relayTuple->s2 = targetSocket;

		thread = CreateThread(NULL, 0, TcpRelayThreadProc, relayTuple, 0, NULL);
		if (thread == NULL) {
			printf("CreateThread() failed: %d\n", GetLastError());
			closesocket(acceptedSocket);
			closesocket(targetSocket);
			free(relayTuple);
			break;
		}

		CloseHandle(thread);
	}

	closesocket(tuple->listener);
	free(tuple);
	return 0;
}

int StartTcpRelay(unsigned short Port)
{
	SOCKET listeningSocket;
	SOCKADDR_IN6 addr6;
	HANDLE thread;
	PLISTENER_TUPLE tuple;

	listeningSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (listeningSocket == INVALID_SOCKET) {
		printf("socket() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	RtlZeroMemory(&addr6, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(Port);
	if (bind(listeningSocket, (PSOCKADDR)&addr6, sizeof(addr6)) == SOCKET_ERROR) {
		printf("bind() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	if (listen(listeningSocket, SOMAXCONN) == SOCKET_ERROR) {
		printf("listen() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	tuple = (PLISTENER_TUPLE)malloc(sizeof(*tuple));
	if (tuple == NULL) {
		return ERROR_OUTOFMEMORY;
	}

	tuple->listener = listeningSocket;
	tuple->port = Port;

	thread = CreateThread(NULL, 0, TcpListenerThreadProc, tuple, 0, NULL);
	if (thread == NULL) {
		printf("CreateThread() failed: %d\n", GetLastError());
		return GetLastError();
	}

	CloseHandle(thread);
	return 0;
}

int
ForwardUdpPacketV4toV6(PUDP_TUPLE tuple,
	                   WSABUF* sourceInfoControlBuffer,
	                   PSOCKADDR_IN6 targetAddress)
{
	DWORD len;
	char buffer[4096];
	WSABUF buf;
	WSAMSG msg;

	buf.buf = buffer;
	buf.len = sizeof(buffer);

	msg.name = NULL;
	msg.namelen = 0;
	msg.lpBuffers = &buf;
	msg.dwBufferCount = 1;
	msg.Control.buf = NULL;
	msg.Control.len = 0;
	msg.dwFlags = 0;
	if (WSARecvMsg(tuple->ipv4Socket, &msg, &len, NULL, NULL) == SOCKET_ERROR) {
		printf("WSARecvMsg() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	msg.name = (PSOCKADDR)targetAddress;
	msg.namelen = sizeof(*targetAddress);
	msg.lpBuffers->len = len;
	msg.Control = *sourceInfoControlBuffer;
	msg.dwFlags = 0;
	if (WSASendMsg(tuple->ipv6Socket, &msg, 0, &len, NULL, NULL) == SOCKET_ERROR) {
		printf("WSASendMsg() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	return 0;
}

int
ForwardUdpPacketV6toV4(PUDP_TUPLE tuple,
	                   PSOCKADDR_IN targetAddress,
	                   /* Out */ WSABUF* destInfoControlBuffer,
	                   /* Out */ PSOCKADDR_IN6 sourceAddress)
{
	DWORD len;
	char buffer[4096];
	WSABUF buf;
	WSAMSG msg;

	buf.buf = buffer;
	buf.len = sizeof(buffer);

	msg.name = (PSOCKADDR)sourceAddress;
	msg.namelen = sizeof(*sourceAddress);
	msg.lpBuffers = &buf;
	msg.dwBufferCount = 1;
	msg.Control = *destInfoControlBuffer;
	msg.dwFlags = 0;
	if (WSARecvMsg(tuple->ipv6Socket, &msg, &len, NULL, NULL) == SOCKET_ERROR) {
		printf("WSARecvMsg() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	// IPV6_PKTINFO must be populated
	assert(WSA_CMSG_FIRSTHDR(&msg)->cmsg_level == IPPROTO_IPV6);
	assert(WSA_CMSG_FIRSTHDR(&msg)->cmsg_type == IPV6_PKTINFO);

	// Copy the returned data length back
	destInfoControlBuffer->len = msg.Control.len;

	msg.name = (PSOCKADDR)targetAddress;
	msg.namelen = sizeof(*targetAddress);
	msg.lpBuffers->len = len;
	msg.Control.buf = NULL;
	msg.Control.len = 0;
	msg.dwFlags = 0;
	if (WSASendMsg(tuple->ipv4Socket, &msg, 0, &len, NULL, NULL) == SOCKET_ERROR) {
		printf("WSASendMsg() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	return 0;
}

DWORD
WINAPI
UdpRelayThreadProc(LPVOID Context)
{
	PUDP_TUPLE tuple = (PUDP_TUPLE)Context;
	fd_set fds;
	int err;
	SOCKADDR_IN6 lastRemote;
	SOCKADDR_IN localTarget;
	char lastSourceBuf[1024];
	WSABUF lastSource;

	printf("UDP relay running for port %d\n", tuple->port);

	RtlZeroMemory(&localTarget, sizeof(localTarget));
	localTarget.sin_family = AF_INET;
	localTarget.sin_port = htons(tuple->port);
	localTarget.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);

	RtlZeroMemory(&lastRemote, sizeof(lastRemote));
	RtlZeroMemory(&lastSource, sizeof(lastSource));

	for (;;) {
		FD_ZERO(&fds);

		FD_SET(tuple->ipv6Socket, &fds);
		FD_SET(tuple->ipv4Socket, &fds);

		err = select(0, &fds, NULL, NULL, NULL);
		if (err <= 0) {
			break;
		}
		else if (FD_ISSET(tuple->ipv6Socket, &fds)) {
			// Forwarding incoming IPv6 packets to the IPv4 port
			// and storing the source address as our current remote
			// target for sending IPv4 data back. Collect the address
			// we received the packet on to be able to send from the same
			// source when we relay.
			lastSource.buf = lastSourceBuf;
			lastSource.len = sizeof(lastSourceBuf);

			// Don't check for errors to prevent transient issues (like GFE not having started yet)
			// from bringing down the whole relay.
			ForwardUdpPacketV6toV4(tuple, &localTarget, &lastSource, &lastRemote);
		}
		else if (FD_ISSET(tuple->ipv4Socket, &fds)) {
			// Forwarding incoming IPv4 packets to the last known
			// address IPv6 address we've heard from. Pass the destination data
			// from the last v6 packet we received to use as the source address.

			// Don't check for errors to prevent transient issues (like GFE not having started yet)
			// from bringing down the whole relay.
			ForwardUdpPacketV4toV6(tuple, &lastSource, &lastRemote);
		}
	}

	closesocket(tuple->ipv6Socket);
	closesocket(tuple->ipv4Socket);
	free(tuple);
	return 0;
}

int StartUdpRelay(unsigned short Port)
{
	SOCKET ipv6Socket;
	SOCKET ipv4Socket;
	SOCKADDR_IN6 addr6;
	SOCKADDR_IN addr;
	PUDP_TUPLE tuple;
	HANDLE thread;
	GUID wsaRecvMsgGuid = WSAID_WSARECVMSG;
	DWORD bytesReturned;
	DWORD val;

	ipv6Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (ipv6Socket == INVALID_SOCKET) {
		printf("socket() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	if (WSAIoctl(ipv6Socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &wsaRecvMsgGuid, sizeof(wsaRecvMsgGuid),
		         &WSARecvMsg, sizeof(WSARecvMsg), &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
		printf("WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, WSARecvMsg) failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	// IPV6_PKTINFO is required to ensure that the destination IPv6 address matches the source that
	// we send our reply from. If we don't do this, traffic destined to addresses that aren't the default
	// outgoing NIC/address will get dropped by the remote party.
	val = TRUE;
	if (setsockopt(ipv6Socket, IPPROTO_IPV6, IPV6_PKTINFO, (char*)&val, sizeof(val)) == SOCKET_ERROR) {
		printf("setsockopt(IPV6_PKTINFO) failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	RtlZeroMemory(&addr6, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(Port);
	if (bind(ipv6Socket, (PSOCKADDR)&addr6, sizeof(addr6)) == SOCKET_ERROR) {
		printf("bind() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	ipv4Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ipv4Socket == INVALID_SOCKET) {
		printf("socket() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	RtlZeroMemory(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
	if (bind(ipv4Socket, (PSOCKADDR)&addr, sizeof(addr)) == SOCKET_ERROR) {
		printf("bind() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	tuple = (PUDP_TUPLE)malloc(sizeof(*tuple));
	if (tuple == NULL) {
		return ERROR_OUTOFMEMORY;
	}

	tuple->ipv4Socket = ipv4Socket;
	tuple->ipv6Socket = ipv6Socket;
	tuple->port = Port;

	thread = CreateThread(NULL, 0, UdpRelayThreadProc, tuple, 0, NULL);
	if (thread == NULL) {
		printf("CreateThread() failed: %d\n", GetLastError());
		return GetLastError();
	}

	CloseHandle(thread);

	return 0;
}

void NETIOAPI_API_ IpInterfaceChangeNotificationCallback(PVOID context, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE)
{
	SetEvent((HANDLE)context);
}

void UPnPCreatePinholeForPort(struct UPNPUrls* urls, struct IGDdatas* data, int proto, const char* myAddr, int port)
{
	char uniqueId[8];
	char protoStr[3];
	char portStr[6];

	snprintf(portStr, sizeof(portStr), "%d", port);
	snprintf(protoStr, sizeof(protoStr), "%d", proto);

	printf("Creating UPnP IPv6 pinhole for %s %s -> %s...", protoStr, portStr, myAddr);

	// Lease time is in seconds - 7200 = 2 hours
	int err = UPNP_AddPinhole(urls->controlURL_6FC, data->IPv6FC.servicetype, "", "0", myAddr, portStr, protoStr, "7200", uniqueId);
	if (err == UPNPCOMMAND_SUCCESS) {
		printf("OK\n");
	}
	else {
		printf("ERROR %d (%s)\n", err, strupnperror(err));
	}
}

void UPnPCreatePinholesForInterface(struct UPNPUrls* urls, struct IGDdatas* data, const char* tmpAddr)
{
	union {
		IP_ADAPTER_ADDRESSES addresses;
		char buffer[8192];
	};
	ULONG error;
	ULONG length;
	PIP_ADAPTER_ADDRESSES currentAdapter;
	PIP_ADAPTER_UNICAST_ADDRESS currentAddress;
	in6_addr targetAddress;

	inet_pton(AF_INET6, tmpAddr, &targetAddress);

	// Get a list of all interfaces with IPv6 addresses on the system
	length = sizeof(buffer);
	error = GetAdaptersAddresses(AF_INET6,
		GAA_FLAG_SKIP_ANYCAST |
		GAA_FLAG_SKIP_MULTICAST |
		GAA_FLAG_SKIP_DNS_SERVER |
		GAA_FLAG_SKIP_FRIENDLY_NAME,
		NULL,
		&addresses,
		&length);
	if (error != ERROR_SUCCESS) {
		printf("GetAdaptersAddresses() failed: %d\n", error);
		return;
	}

	currentAdapter = &addresses;
	currentAddress = nullptr;
	while (currentAdapter != nullptr) {
		// First, search for the adapter
		currentAddress = currentAdapter->FirstUnicastAddress;
		while (currentAddress != nullptr) {
			assert(currentAddress->Address.lpSockaddr->sa_family == AF_INET6);

			PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)currentAddress->Address.lpSockaddr;

			if (RtlEqualMemory(&currentAddrV6->sin6_addr, &targetAddress, sizeof(targetAddress))) {
				// Found interface with matching address
				break;
			}

			currentAddress = currentAddress->Next;
		}

		if (currentAddress != nullptr) {
			// Get out of the loop if we found the matching address
			break;
		}

		currentAdapter = currentAdapter->Next;
	}

	if (currentAdapter == nullptr) {
		printf("No adapter found with IPv6 address: %s\n", tmpAddr);
		return;
	}

	// Now currentAdapter is the adapter we reached the IGD with. Create pinholes for all
	// public IPv6 addresses on this interface using this IGD.
	currentAddress = currentAdapter->FirstUnicastAddress;
	while (currentAddress != nullptr) {
		assert(currentAddress->Address.lpSockaddr->sa_family == AF_INET6);

		PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)currentAddress->Address.lpSockaddr;

		// Exclude link-local addresses
		if (currentAddrV6->sin6_scope_id == 0) {
			char currentAddrStr[128] = {};

			inet_ntop(AF_INET6, &currentAddrV6->sin6_addr, currentAddrStr, sizeof(currentAddrStr));

			for (int i = 0; i < ARRAYSIZE(TCP_PORTS); i++) {
				UPnPCreatePinholeForPort(urls, data, IPPROTO_TCP, currentAddrStr, TCP_PORTS[i]);
			}
			for (int i = 0; i < ARRAYSIZE(UDP_PORTS); i++) {
				UPnPCreatePinholeForPort(urls, data, IPPROTO_UDP, currentAddrStr, UDP_PORTS[i]);
			}
		}

		currentAddress = currentAddress->Next;
	}
}

void UpdateUpnpPinholes()
{
	int upnpErr;
	struct UPNPUrls urls;
	struct IGDdatas data;
	char localAddress[128];
	char ipv6WanAddr[128] = {};

	struct UPNPDev* ipv6Devs = upnpDiscoverAll(5000, nullptr, nullptr, UPNP_LOCAL_PORT_ANY, 1, 2, &upnpErr);
	printf("UPnP IPv6 IGD discovery completed with error code: %d\n", upnpErr);

	int ret = UPNP_GetValidIGD(ipv6Devs, &urls, &data, localAddress, sizeof(localAddress));
	if (ret == 0) {
		printf("No UPnP device found!\n");
		freeUPNPDevlist(ipv6Devs);
		return;
	}
	else if (ret == 3) {
		printf("No UPnP IGD found!\n");
		FreeUPNPUrls(&urls);
		freeUPNPDevlist(ipv6Devs);
		return;
	}
	else if (ret == 1) {
		printf("Found a connected UPnP IGD\n");
	}
	else if (ret == 2) {
		printf("Found a disconnected UPnP IGD (!)\n");
	}
	else {
		printf("UPNP_GetValidIGD() failed: %d\n", ret);
		freeUPNPDevlist(ipv6Devs);
		return;
	}

	// Don't try IPv6FC without a control URL
	if (data.IPv6FC.controlurl[0] != 0) {
		int firewallEnabled, pinholeAllowed;
		
		// Check if this firewall supports IPv6 pinholes
		ret = UPNP_GetFirewallStatus(urls.controlURL_6FC, data.IPv6FC.servicetype, &firewallEnabled, &pinholeAllowed);
		if (ret == UPNPCOMMAND_SUCCESS) {
			printf("UPnP IPv6 firewall control available. Firewall is %s, pinhole is %s\n",
				firewallEnabled ? "enabled" : "disabled",
				pinholeAllowed ? "allowed" : "disallowed");

			if (pinholeAllowed) {
				// If the IGD supports IPv6 pinholes, create them for all IPv6 addresses on this interface
				UPnPCreatePinholesForInterface(&urls, &data, localAddress);
			}
		}
		else {
			printf("UPnP IPv6 firewall control is unavailable with error %d (%s)\n", ret, strupnperror(ret));
		}
	}
	else {
		printf("IPv6 firewall control not supported by UPnP IGD!\n");
	}

	FreeUPNPUrls(&urls);
	freeUPNPDevlist(ipv6Devs);
}

void UpdatePcpPinholes()
{
	union {
		IP_ADAPTER_ADDRESSES addresses;
		char buffer[8192];
	};
	ULONG error;
	ULONG length;
	PIP_ADAPTER_ADDRESSES currentAdapter;
	PIP_ADAPTER_UNICAST_ADDRESS currentAddress;

	// Get all IPv6 interfaces
	length = sizeof(buffer);
	error = GetAdaptersAddresses(AF_INET6,
		GAA_FLAG_SKIP_ANYCAST |
		GAA_FLAG_SKIP_MULTICAST |
		GAA_FLAG_SKIP_DNS_SERVER |
		GAA_FLAG_SKIP_FRIENDLY_NAME |
		GAA_FLAG_INCLUDE_GATEWAYS,
		NULL,
		&addresses,
		&length);
	if (error != ERROR_SUCCESS) {
		printf("GetAdaptersAddresses() failed: %d\n", error);
		return;
	}

	currentAdapter = &addresses;
	while (currentAdapter != NULL) {
		// Skip over interfaces with no gateway
		if (currentAdapter->FirstGatewayAddress == NULL) {
			currentAdapter = currentAdapter->Next;
			continue;
		}

		PSOCKADDR_IN6 gatewayAddrV6 = (PSOCKADDR_IN6)currentAdapter->FirstGatewayAddress->Address.lpSockaddr;

		char addressStr[128];
		inet_ntop(AF_INET6, &gatewayAddrV6->sin6_addr, addressStr, sizeof(addressStr));

		printf("Using PCP server: %s%%%d\n", addressStr, gatewayAddrV6->sin6_scope_id);

		// Create pinholes for all IPv6 GUAs
		currentAddress = currentAdapter->FirstUnicastAddress;
		while (currentAddress != NULL) {
			assert(currentAddress->Address.lpSockaddr->sa_family == AF_INET6);

			PSOCKADDR_IN6 currentAddrV6 = (PSOCKADDR_IN6)currentAddress->Address.lpSockaddr;

			// Exclude link-local addresses
			if (currentAddrV6->sin6_scope_id == 0) {
				inet_ntop(AF_INET6, &currentAddrV6->sin6_addr, addressStr, sizeof(addressStr));
				printf("Updating PCP mappings for address %s\n", addressStr);

				for (int i = 0; i < ARRAYSIZE(TCP_PORTS); i++) {
					PCPMapPort(
						(PSOCKADDR_STORAGE)currentAddrV6,
						currentAddress->Address.iSockaddrLength,
						(PSOCKADDR_STORAGE)currentAdapter->FirstGatewayAddress->Address.lpSockaddr,
						currentAdapter->FirstGatewayAddress->Address.iSockaddrLength,
						IPPROTO_TCP,
						TCP_PORTS[i],
						true,
						false);
				}
				for (int i = 0; i < ARRAYSIZE(UDP_PORTS); i++) {
					PCPMapPort(
						(PSOCKADDR_STORAGE)currentAddrV6,
						currentAddress->Address.iSockaddrLength,
						(PSOCKADDR_STORAGE)currentAdapter->FirstGatewayAddress->Address.lpSockaddr,
						currentAdapter->FirstGatewayAddress->Address.iSockaddrLength,
						IPPROTO_UDP,
						UDP_PORTS[i],
						true,
						false);
				}
			}

			currentAddress = currentAddress->Next;
		}

		currentAdapter = currentAdapter->Next;
	}
}

void ResetLogFile()
{
	char oldLogFilePath[MAX_PATH + 1];
	char currentLogFilePath[MAX_PATH + 1];
	char timeString[MAX_PATH + 1] = {};
	SYSTEMTIME time;

	ExpandEnvironmentStringsA("%ProgramData%\\MISS\\GSv6Fwd-old.log", oldLogFilePath, sizeof(oldLogFilePath));
	ExpandEnvironmentStringsA("%ProgramData%\\MISS\\GSv6Fwd-current.log", currentLogFilePath, sizeof(currentLogFilePath));

	// Close the existing stdout handle. This is important because otherwise
	// it may still be open as stdout when we try to MoveFileEx below.
	fclose(stdout);

	// Rotate the current to the old log file
	MoveFileExA(currentLogFilePath, oldLogFilePath, MOVEFILE_REPLACE_EXISTING);

	// Redirect stdout to this new file
	freopen(currentLogFilePath, "w", stdout);

	// Print a log header
	printf("IPv6 Forwarder for GameStream v" VER_VERSION_STR "\n");

	// Print the current time
	GetSystemTime(&time);
	GetTimeFormatA(LOCALE_SYSTEM_DEFAULT, 0, &time, "hh':'mm':'ss tt", timeString, ARRAYSIZE(timeString));
	printf("The current UTC time is: %s\n", timeString);
}

int Run(void)
{
	int err;
	WSADATA data;

	ResetLogFile();

	HANDLE ifaceChangeEvent = CreateEvent(nullptr, true, false, nullptr);

	err = WSAStartup(MAKEWORD(2, 0), &data);
	if (err == SOCKET_ERROR) {
		printf("WSAStartup() failed: %d\n", err);
		return err;
	}

	// Watch for IPv6 address and interface changes
	HANDLE ifaceChangeHandle;
	NotifyIpInterfaceChange(AF_INET6, IpInterfaceChangeNotificationCallback, ifaceChangeEvent, false, &ifaceChangeHandle);

	// Ensure we get adequate CPU time even when the PC is heavily loaded
	SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

	for (int i = 0; i < ARRAYSIZE(TCP_PORTS); i++) {
		err = StartTcpRelay(TCP_PORTS[i]);
		if (err != 0) {
			printf("Failed to start relay on TCP %d: %d\n", TCP_PORTS[i], err);
			return err;
		}
	}

	for (int i = 0; i < ARRAYSIZE(UDP_PORTS); i++) {
		err = StartUdpRelay(UDP_PORTS[i]);
		if (err != 0) {
			printf("Failed to start relay on UDP %d: %d\n", UDP_PORTS[i], err);
			return err;
		}
	}

	for (;;) {
		ResetEvent(ifaceChangeEvent);
		UpdatePcpPinholes();
		UpdateUpnpPinholes();

		printf("Going to sleep...\n");
		fflush(stdout);

		if (WaitForSingleObject(ifaceChangeEvent, 120 * 1000) == WAIT_FAILED) {
			break;
		}

		ResetLogFile();
	}

	return 0;
}

static SERVICE_STATUS_HANDLE ServiceStatusHandle;
static SERVICE_STATUS ServiceStatus;

DWORD
WINAPI
HandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
	switch (dwControl)
	{
	case SERVICE_CONTROL_INTERROGATE:
		return NO_ERROR;

	case SERVICE_CONTROL_STOP:
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
		return NO_ERROR;

	default:
		return NO_ERROR;
	}
}

VOID
WINAPI
ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
	int err;
	
	ServiceStatusHandle = RegisterServiceCtrlHandlerEx(SERVICE_NAME, HandlerEx, NULL);
	if (ServiceStatusHandle == NULL) {
		printf("RegisterServiceCtrlHandlerEx() failed: %d\n", GetLastError());
		return;
	}

	ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwWin32ExitCode = NO_ERROR;
	ServiceStatus.dwWaitHint = 0;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	ServiceStatus.dwCheckPoint = 0;

	// Tell SCM we're running
	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(ServiceStatusHandle, &ServiceStatus);

	// Start the relay
	err = Run();
	if (err != 0) {
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		ServiceStatus.dwWin32ExitCode = err;
		SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
		return;
	}
}


static const SERVICE_TABLE_ENTRY ServiceTable[] = {
	{ SERVICE_NAME, ServiceMain },
	{ NULL, NULL }
};

int main(int argc, char* argv[])
{
	if (argc == 2 && !strcmp(argv[1], "exe")) {
		Run();
		return 0;
	}

	return StartServiceCtrlDispatcher(ServiceTable);
}

