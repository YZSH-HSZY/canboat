#include <stdio.h>
#include "common.h"
#include "actisense.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <tchar.h>
#define SERIAL_TYPE HANDLE
#pragma comment(lib, "ws2_32.lib")
#else
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <stdint.h>
#define SERIAL_TYPE int
#endif

#define USE_KC2W_PC_DST_UDP_PORT 9998
#define ACTISENCE_PAIR_COM_NAME "COM9"

#ifndef TYPE_U32
   typedef unsigned int          U32;
   #define  TYPE_U32
#endif

#ifdef _WIN32
#define ERROR_PRINT(str_info) printf(str_info ":%d\n", WSAGetLastError());
#define SOCKET_CLOSE(sock) {if(sock != INVALID_SOCKET) closesocket(sock); WSACleanup();}
#else
#define ERROR_PRINT(str_info) perror(str_info);
#define SOCKET_CLOSE(sock) close(sock);
#endif

static int RUN_SIGN = 1;
static bool     isEBL;

typedef struct{
    U32     validCheck1;   // 0xAAAAAAAA
    U32     id;
    int     len;
    char    buf[8];
    U32     validCheck2;   // 0xAAAAAAAA
}stEthCanFrame;

#ifndef _WIN32
void global_clear(int sig) {
    printf("clear\n");
    RUN_SIGN = 0;
}
#else
BOOL WINAPI global_clear(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        printf("clear\n");
        RUN_SIGN = 0;
        return TRUE;
    }
    return FALSE;
}
#endif  // WIN32

#ifdef _WIN32
HANDLE open_serial(LPTSTR pzName, DWORD dwBaudRate, BYTE biDataBits, BYTE biStopBits, BYTE biParity) {
  HANDLE hUART;
	DCB	dcb;
	COMMTIMEOUTS timeout;
  TCHAR szPortName[32];
  wsprintf(szPortName,_T("\\\\.\\%s"),pzName);
  
	hUART = CreateFile(szPortName,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
	if((hUART==INVALID_HANDLE_VALUE)||(hUART==NULL))
	{
		return NULL;
	}
	
	GetCommState(hUART, &dcb);
	dcb.BaudRate = dwBaudRate;
	dcb.Parity   = biParity;
	dcb.ByteSize = biDataBits;
	dcb.StopBits = biStopBits;
	SetCommState(hUART, &dcb);

	GetCommTimeouts(hUART, &timeout);
	timeout.ReadIntervalTimeout = MAXDWORD;
	timeout.ReadTotalTimeoutMultiplier = 0;
	timeout.ReadTotalTimeoutConstant = 0;
	timeout.WriteTotalTimeoutConstant = 0;
	timeout.WriteTotalTimeoutMultiplier = 0;
	SetCommTimeouts(hUART,&timeout);
	SetupComm(hUART,1024,1024);
	PurgeComm(hUART,PURGE_RXCLEAR | PURGE_TXCLEAR);
	
	return hUART;
}
DWORD  WRITE(HANDLE hUART, void* pData, DWORD dwLen)
{
	BOOL	biRet;
	DWORD	dwWrite;

	biRet = WriteFile(hUART,pData,dwLen,&dwWrite,NULL);
	return biRet?dwWrite:0;
}
void close_serial(HANDLE hUART)
{
	CloseHandle(hUART);
}
#endif

static size_t writeUint64(uint64_t v, unsigned char *buf)
{
  size_t out = 0;
  for (int byte = 0; byte < 8; byte++)
  {
    uint8_t c = (uint8_t) v;
    if (c == ESC)
    {
      *buf++ = c;
      out++;
    }
    *buf++ = c;
    out++;
    v = v >> 8;
  }
  return out;
}

/*
 * Wrap the PGN or NGT message and send to NGT
 */
static void writeMessage(SERIAL_TYPE handle, unsigned char command, const unsigned char *cmd, const size_t len, uint64_t when)
{
  unsigned char  bst[255];
  unsigned char *b = bst;
  unsigned char *r = bst;
  unsigned char  crc;

  int i;

  if (isEBL)
  {
    if (when == 0)
    {
      when = getNow();
    }
    // Prepend with timestamp
    when = (when + UINT64_C(11644473600000)) * UINT64_C(10000);

    *b++ = ESC;
    *b++ = SOH;
    *b++ = EBL_TIMESTAMP;
    b += writeUint64(when, b);
    *b++ = ESC;
    *b++ = LF;
  }

  *b++ = DLE;
  *b++ = STX;
  *b++ = command;
  crc  = command;
  *b++ = len;
  if (len == DLE)
  {
    *b++ = DLE;
  }

  for (i = 0; i < len; i++)
  {
    if (cmd[i] == DLE)
    {
      *b++ = DLE;
    }
    *b++ = cmd[i];
    crc += (unsigned char) cmd[i];
  }

  crc += i;

  crc = 256 - (int) crc;
  if (crc == DLE)
  {
    *b++ = DLE;
  }
  *b++ = crc;
  *b++ = DLE;
  *b++ = ETX;

  int retryCount    = 5;
  int needs_written = b - bst;
  int written;
  do
  {
    written = WRITE(handle, r, needs_written);
    if (written != -1)
    {
      r += written;
      needs_written -= written;
    }
    else if (errno == EAGAIN)
    {
      retryCount--;
      usleep(25000);
    }
    else
    {
      break;
    }

  } while (needs_written > 0 && retryCount >= 0);

  if (written == -1)
  {
    logError("Unable to write command '%.*s' to NGT-1-A device\n", (int) len, cmd);
  }

  logDebug("Written command %X len %d\n", command, (int) len);
}

static void parseAndWriteIn(SERIAL_TYPE handle, const char *cmd)
{
  unsigned char  msg[500];
  unsigned char *m;

  unsigned int prio;
  unsigned int pgn;
  unsigned int src;
  unsigned int dst;
  unsigned int bytes;

  char        *p;
  int          i;
  int          b;
  unsigned int byt;
  int          r;
  uint64_t     when = 0;

  if (!cmd || !*cmd || *cmd == '\n')
  {
    return;
  }

  parseTimestamp(cmd, &when);
  p = strchr(cmd, ',');
  if (!p)
  {
    return;
  }

  r = sscanf(p, ",%u,%u,%u,%u,%u,%n", &prio, &pgn, &src, &dst, &bytes, &i);
  logDebug("parseAndWriteIn %.20s = %d\n", p, r);
  if (r == 5)
  {
    if (pgn >= ACTISENSE_BEM)
    { // Ignore synthetic CANboat PGNs that report original device status.
      return;
    }

    p += i - 1;
    m    = msg;
    *m++ = (unsigned char) prio;
    *m++ = (unsigned char) pgn;
    *m++ = (unsigned char) (pgn >> 8);
    *m++ = (unsigned char) (pgn >> 16);
    *m++ = (unsigned char) dst;
    //*m++ = (unsigned char) 0;
    *m++ = (unsigned char) bytes;
    for (b = 0; m < msg + sizeof(msg) && b < bytes; b++)
    {
      if ((sscanf(p, ",%x%n", &byt, &i) == 1) && (byt < 256))
      {
        *m++ = byt;
      }
      else
      {
        logError("Unable to parse incoming message '%s' at offset %u\n", cmd, b);
        return;
      }
      p += i;
    }
  }
  else
  {
    logError("Unable to parse incoming message '%s', r = %d\n", cmd, r);
    return;
  }

  logDebug("About to write:  %s\n", cmd);
  writeMessage(handle, N2K_MSG_SEND, msg, m - msg, when);
}

bool valid_kc2w_udp_frame(const unsigned char *msg, size_t msgLen) {
  if (msgLen < sizeof(stEthCanFrame)) return false;
  stEthCanFrame rev;
  memcpy(&rev, msg, sizeof(stEthCanFrame));
  if(rev.validCheck1 != 0xaaaaaaaa || rev.validCheck2 != 0xaaaaaaaa) return false;
  return true;
}

void handle_one_frame(SERIAL_TYPE handle, const unsigned char *msg, size_t msgLen) {
  if (!valid_kc2w_udp_frame(msg, msgLen)) return;
  
}

int main(int argc, char **argv) {
    printf("hello\n");

#ifndef _WIN32
    signal(SIGSEGV, global_clear);
    signal(SIGINT, global_clear);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0){
        perror("socket");
        return 1;
    }
#else
    if (!SetConsoleCtrlHandler(global_clear, TRUE)) {
        printf("set console signal handler failed\n");
        return 1;
    }
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        printf("socket failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    SERIAL_TYPE handle = open_serial(ACTISENCE_PAIR_COM_NAME, 115200, 8, 1, 0);
    if (handle == NULL) {
        printf("open_serial failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }
#endif

    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(USE_KC2W_PC_DST_UDP_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        ERROR_PRINT("bind");
        SOCKET_CLOSE(sock);
        return 1;
    }
    
    fd_set fds;
    struct timeval tv = {0, 200};

    while(RUN_SIGN) {
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        
        int ret = select(sock + 1, &fds, NULL, NULL, &tv);

        if(ret < 0){
            ERROR_PRINT("select failed with error");
            break;
        }
        else if(ret == 0){
            continue;
        }

        char buf[1024];
        struct sockaddr_in dst_addr;
        socklen_t len = sizeof(dst_addr);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&dst_addr, &len);
        if(n < 0){
            ERROR_PRINT("recvfrom failed with error");
            break;
        }
        buf[n] = 0;
        printf("from %s:%d: %s\n", inet_ntoa(dst_addr.sin_addr), ntohs(dst_addr.sin_port), buf);
        handle_one_frame(handle, (const unsigned char *)buf, n);
    }

    SOCKET_CLOSE(sock);
    close_serial(handle);
    printf("bye\n");

    return 0;
}
