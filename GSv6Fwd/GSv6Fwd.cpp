#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#pragma comment(lib, "ws2_32")
#include <WinSock2.h>
#include <Ws2ipdef.h>
#include <WS2tcpip.h>

#pragma comment(lib, "iphlpapi")
#include <Iphlpapi.h>

#define SERVICE_NAME L"GSv6FwdSvc"

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
		fprintf(stderr, "getsockname() failed: %d\n", WSAGetLastError());
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
		fprintf(stderr, "GetAdaptersAddresses() failed: %d\n", error);
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
		fprintf(stderr, "Unable to find incoming interface\n");
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
	fprintf(stderr, "WARNING: No IPv4 connectivity on incoming interface\n");
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
			fprintf(stderr, "accept() failed: %d\n", WSAGetLastError());
			break;
		}

		targetSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (targetSocket == INVALID_SOCKET) {
			fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
			closesocket(acceptedSocket);
			continue;
		}

		RtlZeroMemory(&targetAddress, sizeof(targetAddress));
		targetAddress.sin_family = AF_INET;
		targetAddress.sin_port = htons(tuple->port);
		if (FindLocalAddressBySocket(acceptedSocket, &targetAddress.sin_addr) != 0) {
			continue;
		}

		if (connect(targetSocket, (PSOCKADDR)&targetAddress, sizeof(targetAddress)) == SOCKET_ERROR) {
			fprintf(stderr, "connect() failed: %d\n", WSAGetLastError());
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
		if (thread == INVALID_HANDLE_VALUE) {
			fprintf(stderr, "CreateThread() failed: %d\n", GetLastError());
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
		fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	RtlZeroMemory(&addr6, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(Port);
	if (bind(listeningSocket, (PSOCKADDR)&addr6, sizeof(addr6)) == SOCKET_ERROR) {
		fprintf(stderr, "bind() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	if (listen(listeningSocket, SOMAXCONN) == SOCKET_ERROR) {
		fprintf(stderr, "listen() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	tuple = (PLISTENER_TUPLE)malloc(sizeof(*tuple));
	if (tuple == NULL) {
		return ERROR_OUTOFMEMORY;
	}

	tuple->listener = listeningSocket;
	tuple->port = Port;

	thread = CreateThread(NULL, 0, TcpListenerThreadProc, tuple, 0, NULL);
	if (thread == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "CreateThread() failed: %d\n", GetLastError());
		return GetLastError();
	}

	CloseHandle(thread);
	return 0;
}

int
ForwardUdpPacket(SOCKET from, SOCKET to,
				 PSOCKADDR target, int targetLen,
				 PSOCKADDR source, int sourceLen)
{
	int len;
	char buffer[4096];

	len = recvfrom(from, buffer, sizeof(buffer), 0, source, &sourceLen);
	if (len < 0) {
		fprintf(stderr, "recvfrom() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	if (sendto(to, buffer, len, 0, target, targetLen) != len) {
		fprintf(stderr, "sendto() failed: %d\n", WSAGetLastError());
		// Fake success, since we may just be waiting for a target address
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

	printf("UDP relay running for port %d\n", tuple->port);

	RtlZeroMemory(&localTarget, sizeof(localTarget));
	localTarget.sin_family = AF_INET;
	localTarget.sin_port = htons(tuple->port);
	localTarget.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);

	RtlZeroMemory(&lastRemote, sizeof(lastRemote));

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
			// target for sending IPv4 data back.
			err = ForwardUdpPacket(tuple->ipv6Socket, tuple->ipv4Socket,
				(PSOCKADDR)&localTarget, sizeof(localTarget),
				(PSOCKADDR)&lastRemote, sizeof(lastRemote));
			if (err < 0) {
				break;
			}
		}
		else if (FD_ISSET(tuple->ipv4Socket, &fds)) {
			// Forwarding incoming IPv4 packets to the last known
			// address IPv6 address we've heard from. Discard the source.
			SOCKADDR_STORAGE unused;
			err = ForwardUdpPacket(tuple->ipv4Socket, tuple->ipv6Socket,
				(PSOCKADDR)&lastRemote, sizeof(lastRemote),
				(PSOCKADDR)&unused, sizeof(unused));
			if (err < 0) {
				break;
			}
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

	ipv6Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (ipv6Socket == INVALID_SOCKET) {
		fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	RtlZeroMemory(&addr6, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(Port);
	if (bind(ipv6Socket, (PSOCKADDR)&addr6, sizeof(addr6)) == SOCKET_ERROR) {
		fprintf(stderr, "bind() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	ipv4Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ipv4Socket == INVALID_SOCKET) {
		fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
		return WSAGetLastError();
	}

	RtlZeroMemory(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
	if (bind(ipv4Socket, (PSOCKADDR)&addr, sizeof(addr)) == SOCKET_ERROR) {
		fprintf(stderr, "bind() failed: %d\n", WSAGetLastError());
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
	if (thread == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "CreateThread() failed: %d\n", GetLastError());
		return GetLastError();
	}

	CloseHandle(thread);

	return 0;
}

void NETIOAPI_API_ IpInterfaceChangeNotificationCallback(PVOID context, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE)
{
	SetEvent((HANDLE)context);
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
		fprintf(stderr, "GetAdaptersAddresses() failed: %d\n", error);
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

		// Create pinholes for all public IPv6 addresses
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

int Run(void)
{
	int err;
	WSADATA data;

	HANDLE ifaceChangeEvent = CreateEvent(nullptr, true, false, nullptr);

	err = WSAStartup(MAKEWORD(2, 0), &data);
	if (err == SOCKET_ERROR) {
		fprintf(stderr, "WSAStartup() failed: %d\n", err);
		return err;
	}

	// Watch for IPv6 address and interface changes
	HANDLE ifaceChangeHandle;
	NotifyIpInterfaceChange(AF_INET6, IpInterfaceChangeNotificationCallback, ifaceChangeEvent, false, &ifaceChangeHandle);

	for (int i = 0; i < ARRAYSIZE(TCP_PORTS); i++) {
		err = StartTcpRelay(TCP_PORTS[i]);
		if (err != 0) {
			fprintf(stderr, "Failed to start relay on TCP %d: %d\n", TCP_PORTS[i], err);
			return err;
		}
	}

	for (int i = 0; i < ARRAYSIZE(UDP_PORTS); i++) {
		err = StartUdpRelay(UDP_PORTS[i]);
		if (err != 0) {
			fprintf(stderr, "Failed to start relay on UDP %d: %d\n", UDP_PORTS[i], err);
			return err;
		}
	}

	do {
		ResetEvent(ifaceChangeEvent);
		UpdatePcpPinholes();
	} while (WaitForSingleObject(ifaceChangeEvent, 120 * 1000) != WAIT_FAILED);

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
		fprintf(stderr, "RegisterServiceCtrlHandlerEx() failed: %d\n", GetLastError());
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

