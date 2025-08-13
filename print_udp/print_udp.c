#include <stdio.h>
#include "common.h"
#include "actisense.h"
#include "parse.h"

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

#define USE_KC2W_PC_DST_UDP_PORT 9999
#define ACTISENCE_PAIR_COM_NAME "COM4"

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
    unsigned char    buf[8];
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

static char HEX_STR_BUFFER[1024] = {0};
static const char* bytes_to_hex(const char* bytes, size_t len) {
  memset(HEX_STR_BUFFER, 0, sizeof(HEX_STR_BUFFER));
  for (size_t i = 0; i < len; ++i) {
    snprintf(HEX_STR_BUFFER + 2 * i, 3, "%02x", (unsigned char)bytes[i]);
  }
  return HEX_STR_BUFFER;
}

typedef enum{
  SendUnknown,
  ISO,
  Single,
  Mixed,
  Fast
} PgnSendType;
/*
import json
import jsonpath
fs = json.load(open("canboat.json", "r"))
ret = """
static const char* get_pgn_type(uint32_t pgn_no) {
  switch(pgn_no) {
%s
    default: return "Unknown";
  }
};
"""
fs = ""
ss = {_['PGN']:_['Type'] for _ in list(jsonpath.jsonpath(fs,"$..PGNs[*]"))}

lines = ""
for k, v in ss.items():
    lines += f'    case {k}: return "{v}";\n'
print(ret % lines)
*/


static const char* get_pgn_type(uint32_t pgn_no) {
  switch(pgn_no) {
    case 59392: return "Single";
    case 59904: return "Single";
    case 60160: return "Single";
    case 60416: return "Single";
    case 60928: return "Single";
    case 61184: return "Single";
    case 61440: return "Single";
    case 65001: return "Single";
    case 65002: return "Single";
    case 65003: return "Single";
    case 65004: return "Single";
    case 65005: return "Single";
    case 65006: return "Single";
    case 65007: return "Single";
    case 65008: return "Single";
    case 65009: return "Single";
    case 65010: return "Single";
    case 65011: return "Single";
    case 65012: return "Single";
    case 65013: return "Single";
    case 65014: return "Single";
    case 65015: return "Single";
    case 65016: return "Single";
    case 65017: return "Single";
    case 65018: return "Single";
    case 65019: return "Single";
    case 65020: return "Single";
    case 65021: return "Single";
    case 65022: return "Single";
    case 65023: return "Single";
    case 65024: return "Single";
    case 65025: return "Single";
    case 65026: return "Single";
    case 65027: return "Single";
    case 65028: return "Single";
    case 65029: return "Single";
    case 65030: return "Single";
    case 65240: return "ISO";
    case 65280: return "Single";
    case 65284: return "Single";
    case 65285: return "Single";
    case 65286: return "Single";
    case 65287: return "Single";
    case 65288: return "Single";
    case 65289: return "Single";
    case 65290: return "Single";
    case 65292: return "Single";
    case 65293: return "Single";
    case 65302: return "Single";
    case 65305: return "Single";
    case 65309: return "Single";
    case 65312: return "Single";
    case 65340: return "Single";
    case 65341: return "Single";
    case 65345: return "Single";
    case 65350: return "Single";
    case 65359: return "Single";
    case 65360: return "Single";
    case 65361: return "Single";
    case 65371: return "Single";
    case 65374: return "Single";
    case 65379: return "Single";
    case 65408: return "Single";
    case 65409: return "Single";
    case 65410: return "Single";
    case 65420: return "Single";
    case 65480: return "Single";
    case 126208: return "Fast";
    case 126464: return "Fast";
    case 126720: return "Fast";
    case 126976: return "Mixed";
    case 126983: return "Fast";
    case 126984: return "Fast";
    case 126985: return "Fast";
    case 126986: return "Fast";
    case 126987: return "Fast";
    case 126988: return "Fast";
    case 126992: return "Single";
    case 126993: return "Single";
    case 126996: return "Fast";
    case 126998: return "Fast";
    case 127233: return "Fast";
    case 127237: return "Fast";
    case 127245: return "Single";
    case 127250: return "Single";
    case 127251: return "Single";
    case 127252: return "Single";
    case 127257: return "Single";
    case 127258: return "Single";
    case 127488: return "Single";
    case 127489: return "Fast";
    case 127490: return "Fast";
    case 127491: return "Fast";
    case 127493: return "Single";
    case 127494: return "Fast";
    case 127495: return "Fast";
    case 127496: return "Fast";
    case 127497: return "Fast";
    case 127498: return "Fast";
    case 127500: return "Single";
    case 127501: return "Single";
    case 127502: return "Single";
    case 127503: return "Fast";
    case 127504: return "Fast";
    case 127505: return "Single";
    case 127506: return "Fast";
    case 127507: return "Fast";
    case 127508: return "Single";
    case 127509: return "Fast";
    case 127510: return "Fast";
    case 127511: return "Fast";
    case 127512: return "Fast";
    case 127513: return "Fast";
    case 127514: return "Fast";
    case 127744: return "Single";
    case 127745: return "Single";
    case 127746: return "Single";
    case 127747: return "Single";
    case 127748: return "Single";
    case 127749: return "Single";
    case 127750: return "Single";
    case 127751: return "Single";
    case 128000: return "Single";
    case 128001: return "Single";
    case 128002: return "Single";
    case 128003: return "Single";
    case 128006: return "Single";
    case 128007: return "Single";
    case 128008: return "Single";
    case 128259: return "Single";
    case 128267: return "Single";
    case 128275: return "Fast";
    case 128520: return "Fast";
    case 128538: return "Fast";
    case 128768: return "Single";
    case 128769: return "Single";
    case 128776: return "Single";
    case 128777: return "Single";
    case 128778: return "Single";
    case 128780: return "Single";
    case 129025: return "Single";
    case 129026: return "Single";
    case 129027: return "Single";
    case 129028: return "Single";
    case 129029: return "Fast";
    case 129033: return "Single";
    case 129038: return "Fast";
    case 129039: return "Fast";
    case 129040: return "Fast";
    case 129041: return "Fast";
    case 129044: return "Fast";
    case 129045: return "Fast";
    case 129283: return "Single";
    case 129284: return "Fast";
    case 129285: return "Fast";
    case 129291: return "Single";
    case 129301: return "Fast";
    case 129302: return "Fast";
    case 129538: return "Fast";
    case 129539: return "Single";
    case 129540: return "Fast";
    case 129541: return "Fast";
    case 129542: return "Fast";
    case 129545: return "Fast";
    case 129546: return "Single";
    case 129547: return "Fast";
    case 129549: return "Fast";
    case 129550: return "Single";
    case 129551: return "Fast";
    case 129556: return "Fast";
    case 129792: return "Fast";
    case 129793: return "Fast";
    case 129794: return "Fast";
    case 129795: return "Fast";
    case 129796: return "Fast";
    case 129797: return "Fast";
    case 129798: return "Fast";
    case 129799: return "Fast";
    case 129800: return "Fast";
    case 129801: return "Fast";
    case 129802: return "Fast";
    case 129803: return "Fast";
    case 129804: return "Fast";
    case 129805: return "Fast";
    case 129806: return "Fast";
    case 129807: return "Fast";
    case 129808: return "Fast";
    case 129809: return "Fast";
    case 129810: return "Fast";
    case 130052: return "Fast";
    case 130053: return "Fast";
    case 130054: return "Fast";
    case 130060: return "Fast";
    case 130061: return "Fast";
    case 130064: return "Fast";
    case 130065: return "Fast";
    case 130066: return "Fast";
    case 130067: return "Fast";
    case 130068: return "Fast";
    case 130069: return "Fast";
    case 130070: return "Fast";
    case 130071: return "Fast";
    case 130072: return "Fast";
    case 130073: return "Fast";
    case 130074: return "Fast";
    case 130306: return "Single";
    case 130310: return "Single";
    case 130311: return "Single";
    case 130312: return "Single";
    case 130313: return "Single";
    case 130314: return "Single";
    case 130315: return "Single";
    case 130316: return "Single";
    case 130320: return "Fast";
    case 130321: return "Fast";
    case 130322: return "Fast";
    case 130323: return "Fast";
    case 130324: return "Fast";
    case 130330: return "Fast";
    case 130560: return "Single";
    case 130561: return "Fast";
    case 130562: return "Fast";
    case 130563: return "Fast";
    case 130564: return "Fast";
    case 130565: return "Fast";
    case 130566: return "Fast";
    case 130567: return "Fast";
    case 130569: return "Fast";
    case 130570: return "Fast";
    case 130571: return "Fast";
    case 130572: return "Fast";
    case 130573: return "Fast";
    case 130574: return "Fast";
    case 130576: return "Single";
    case 130577: return "Fast";
    case 130578: return "Fast";
    case 130579: return "Single";
    case 130580: return "Fast";
    case 130581: return "Fast";
    case 130582: return "Single";
    case 130583: return "Fast";
    case 130584: return "Fast";
    case 130585: return "Single";
    case 130586: return "Fast";
    case 130816: return "Fast";
    case 130817: return "Fast";
    case 130818: return "Fast";
    case 130819: return "Fast";
    case 130820: return "Fast";
    case 130821: return "Fast";
    case 130822: return "Fast";
    case 130823: return "Fast";
    case 130824: return "Fast";
    case 130825: return "Fast";
    case 130827: return "Fast";
    case 130828: return "Fast";
    case 130831: return "Fast";
    case 130832: return "Fast";
    case 130833: return "Fast";
    case 130834: return "Fast";
    case 130835: return "Fast";
    case 130836: return "Fast";
    case 130837: return "Fast";
    case 130838: return "Fast";
    case 130839: return "Fast";
    case 130840: return "Fast";
    case 130842: return "Fast";
    case 130843: return "Fast";
    case 130845: return "Fast";
    case 130846: return "Fast";
    case 130847: return "Fast";
    case 130848: return "Fast";
    case 130850: return "Fast";
    case 130851: return "Fast";
    case 130856: return "Fast";
    case 130860: return "Fast";
    case 130880: return "Fast";
    case 130881: return "Fast";
    case 130918: return "Fast";
    case 130944: return "Fast";

    default: return "Unknown";
  }
};

static enum PgnSendType judge_pgn_type(uint32_t pgn_no) {
  const char* type = get_pgn_type(pgn_no);
  if (strcmp(type, "ISO") == 0) {
    return ISO;
  } else if (strcmp(type, "Single") == 0) {
    return Single;
  } else if (strcmp(type, "Mixed") == 0) {
    return Mixed;
  } else if (strcmp(type, "Fast") == 0) {
    return Fast;
  } else {
    return SendUnknown;
  }
};

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
    logDebug("Trying to write bytes %s\n", bytes_to_hex((const char *)r, needs_written));
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

void get_current_time_formatted(char *buffer, size_t buffer_size) {
    SYSTEMTIME st;
    GetLocalTime(&st); // get local current time(unit ms)

    // YYYY-MM-DD-HH:MM:SS.mmm
    snprintf(buffer, buffer_size, 
             "%04d-%02d-%02d-%02d:%02d:%02d.%03d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond,
             st.wMilliseconds);
}

typedef struct
{
  size_t   size;
  uint8_t  data[FASTPACKET_MAX_SIZE];
  uint32_t frames;    // Bit is one when frame is received
  uint32_t allFrames; // Bit is one when frame needs to be present
  int      pgn;
  int      src;
  bool     used;
} Packet;

#define REASSEMBLY_BUFFER_SIZE (128)

static Packet reassemblyBuffer[REASSEMBLY_BUFFER_SIZE];

static bool handle_fast_pgn(RawMessage* msg, Packet** p) {
  // const Pgn *pgn;
  size_t     buffer;
  // Packet    *p;
  // Fast packet requires re-asssembly
  // We only get here if we know for sure that the PGN is fast-packet
  // Possibly it is of unknown length when the PGN is unknown.

  for (buffer = 0; buffer < REASSEMBLY_BUFFER_SIZE; buffer++)
  {
    *p = &reassemblyBuffer[buffer];

    if ((*p)->used && (*p)->pgn == msg->pgn && (*p)->src == msg->src)
    {
      // Found existing slot
      break;
    }
  }
  if (buffer == REASSEMBLY_BUFFER_SIZE)
  {
    // Find a free slot
    for (buffer = 0; buffer < REASSEMBLY_BUFFER_SIZE; buffer++)
    {
      *p = &reassemblyBuffer[buffer];
      if (!(*p)->used)
      {
        break;
      }
    }
    if (buffer == REASSEMBLY_BUFFER_SIZE)
    {
      logError("Out of reassembly buffers; ignoring PGN %u\n", msg->pgn);
      return false;
    }
    (*p)->used   = true;
    (*p)->src    = msg->src;
    (*p)->pgn    = msg->pgn;
    (*p)->frames = 0;
  }

  {
    // YDWG can receive frames out of order, so handle this.
    uint32_t frame    = msg->data[0] & 0x1f;
    uint32_t seq      = msg->data[0] & 0xe0;
    size_t   idx      = (frame == 0) ? 0 : FASTPACKET_BUCKET_0_SIZE + (frame - 1) * FASTPACKET_BUCKET_N_SIZE;
    size_t   frameLen = (frame == 0) ? FASTPACKET_BUCKET_0_SIZE : FASTPACKET_BUCKET_N_SIZE;
    size_t   msgIdx   = (frame == 0) ? FASTPACKET_BUCKET_0_OFFSET : FASTPACKET_BUCKET_N_OFFSET;

    if (((*p)->frames & (1 << frame)) != 0)
    {
      logError("Received incomplete fast packet PGN %u from source %u\n", msg->pgn, msg->src);
      (*p)->frames = 0;
    }

    if (frame == 0 && (*p)->frames == 0)
    {
      (*p)->size      = msg->data[1];
      (*p)->allFrames = (uint32_t) ((UINT64_C(1) << (1 + ((*p)->size / 7))) - 1);
    }

    memcpy(&(*p)->data[idx], &msg->data[msgIdx], frameLen);
    (*p)->frames |= 1 << frame;

    logDebug("Using buffer %u for reassembly of PGN %u: size %zu frame %u sequence %u idx=%zu frames=%x mask=%x\n",
             buffer,
             msg->pgn,
             (*p)->size,
             frame,
             seq,
             idx,
             (*p)->frames,
             (*p)->allFrames);
    if ((*p)->frames == (*p)->allFrames)
    {
      // Received all data
      return true;
    }
  }
  return false;
}

void handle_one_frame(SERIAL_TYPE handle, const unsigned char *msg, size_t msgLen) {
  if (!valid_kc2w_udp_frame(msg, msgLen)) return;

  stEthCanFrame rev;
  memcpy(&rev, msg, sizeof(stEthCanFrame));
  // "2025-08-08-08:35:49.125,7,126993,21,255,8,60,ac,cf,ff,ff,0f,a0,c0\n"
  char analyzer_str[1024] = {0};
  unsigned int pri = 0;
  unsigned int src = 0;
  unsigned int dst = 255;
  unsigned int pgn = 0;

//   <0x18eeff01> [8] 05 a0 be 1c 00 a0 a0 c0 
// 2025-08-11-08:14:49.622,6,60928,1,255,8,05,a0,be,1c,00,a0,a0,c0

  get_current_time_formatted(analyzer_str, sizeof(analyzer_str));
  getISO11783BitsFromCanId(rev.id, &pri, &pgn, &src, &dst);
  size_t len = strlen(analyzer_str);
  
  PgnSendType send_type = judge_pgn_type(pgn);
  if (send_type == Fast) {
    RawMessage raw_msg;
    raw_msg.prio = pri;
    raw_msg.pgn = pgn;
    raw_msg.src = src;
    raw_msg.dst = dst;
    raw_msg.len = rev.len;
    memcpy(raw_msg.data, rev.buf, min(sizeof(rev.buf), rev.len));
    Packet* p = NULL;
    if(!handle_fast_pgn(&raw_msg, &p)) return;
    else if(p != NULL) {
      sprintf(analyzer_str + len, ",%d,%d,%d,%d,%d", pri, p->pgn, p->src, dst, (uint32_t)p->size);
      len = strlen(analyzer_str);
      sprintf(analyzer_str + len, ",%d", p->frames);
      for (int i = 0; i < p->size; i++)
      {
        if(i >= sizeof(p->data)/sizeof(p->data[0])) {
          printf("too long data, only print first %lld bytes\n", sizeof(p->data)/sizeof(p->data[0]));
          break;
        }
        sprintf(analyzer_str + len, ",%02x", (unsigned char)p->data[i]);
        len += 3;
      }
      analyzer_str[len] = '\0';
      p->used   = false;
      p->frames = 0;
    }
  }
  else if(send_type == Single) {
    sprintf(analyzer_str + len, ",%d,%d,%d,%d,%d", pri, pgn, src, dst, rev.len);
    len = strlen(analyzer_str);
    for (int i = 0; i < rev.len; i++)
    {
      if(i >= sizeof(rev.buf)/sizeof(rev.buf[0])) {
        printf("too long data, only print first %lld bytes\n", sizeof(rev.buf)/sizeof(rev.buf[0]));
        break;
      }
      sprintf(analyzer_str + len, ",%02x", (unsigned char)rev.buf[i]);
      len += 3;
    }
    analyzer_str[len] = '\0';
  }
  else {
    return;
  }
  parseAndWriteIn(handle, (const char *)&analyzer_str);
}

static char VIRTUAL_COM_NAME[32] = "COM4";
static int VIRTUAL_COM_BAUD = 115200;
static int KC2W_PC_DST_UDP_PORT = 9999;

// load config, format:
// COM4,4800,9999
void load_config(char* file_path) {
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    printf("Failed to open config file: %s\n", file_path);
    return;
  }

  char line[1024];
  while (fgets(line, sizeof(line), fp)) {
    char *token = strtok(line, ",");
    if (token != NULL) {
      strcpy(VIRTUAL_COM_NAME, token);
      token = strtok(NULL, ",");
      if (token != NULL) {
        int baud = atoi(token);
        if (baud > 0) {
          VIRTUAL_COM_BAUD = baud;
        }
      }
      token = strtok(NULL, ",");
      if (token != NULL) {
        int port = atoi(token);
        if (port > 0) {
          KC2W_PC_DST_UDP_PORT = port;
        }
      }
    }
  }

  fclose(fp);
}

int main(int argc, char **argv) {
    printf("hello, load config from config.txt\n");
    load_config("config.txt");
    printf("Config Virtual COM name: %s\n", VIRTUAL_COM_NAME);
    printf("Config Virtual COM baud: %d\n", VIRTUAL_COM_BAUD);
    printf("Config KC2W PC DST UDP port name: %d\n", KC2W_PC_DST_UDP_PORT);
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
    SERIAL_TYPE handle = open_serial(VIRTUAL_COM_NAME, VIRTUAL_COM_BAUD, 8, 1, 0);
    if (handle == NULL) {
        printf("open_serial failed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }
#endif

    setLogLevel(LOGLEVEL_DEBUG);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(KC2W_PC_DST_UDP_PORT);
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
        printf("from %s:%d: len=%d\n", inet_ntoa(dst_addr.sin_addr), ntohs(dst_addr.sin_port), n);
        handle_one_frame(handle, (const unsigned char *)buf, n);
    }

    SOCKET_CLOSE(sock);
    close_serial(handle);
    printf("bye\n");

    return 0;
}

// 00/01/02/03/04/05/06
// 20/21/22/23/24/25/26
// 40/41/42/43/44/45/46
// 45/46/60/61/62/63
