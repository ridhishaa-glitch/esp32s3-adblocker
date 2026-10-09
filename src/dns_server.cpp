#include "dns_server.h"
#include "config.h"
#include "blocklist.h"
#include "stats.h"
#include <lwip/sockets.h>
#include <lwip/netdb.h>

#define DNS_PORT      53
#define MAX_PENDING   256
#define PENDING_TTL_MS 5000
#define BUF_SIZE      600

struct Pending {
  bool inUse;
  uint16_t sentId;         // id we put on the wire to upstream
  uint16_t origId;         // client's original id
  struct sockaddr_in cli;  // where to send the reply
  uint32_t ts;             // millis when created
};

static int gListenSock = -1;
static int gUpSock = -1;
static Pending gPending[MAX_PENDING];
static uint8_t gNonce = 0;

String ipToStr(uint32_t ip) {
  char b[16];
  snprintf(b, sizeof(b), "%u.%u.%u.%u",
           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
  return String(b);
}

// Parse the question's QNAME into dotted form; returns bytes consumed to the
// end of the question (name + qtype + qclass), or -1 on malformed input.
static int parseQuestion(const uint8_t* buf, int len, char* name, int nameMax, uint16_t* qtype) {
  int pos = 12;  // skip header
  int n = 0;
  while (pos < len) {
    uint8_t l = buf[pos++];
    if (l == 0) break;
    if (l & 0xC0) return -1;              // compression not allowed in question
    if (pos + l > len) return -1;
    if (n && n < nameMax - 1) name[n++] = '.';
    for (int i = 0; i < l && n < nameMax - 1; i++) name[n++] = buf[pos + i];
    pos += l;
  }
  name[n] = 0;
  if (pos + 4 > len) return -1;
  *qtype = (buf[pos] << 8) | buf[pos + 1];
  return pos + 4;  // end of question
}

static bool resolveUpstream(struct sockaddr_in* out) {
  const char* ip = gConfig.upstream1.c_str();
  if (inet_aton(ip, &out->sin_addr) == 0) {
    if (inet_aton(gConfig.upstream2.c_str(), &out->sin_addr) == 0) return false;
  }
  out->sin_family = AF_INET;
  out->sin_port = htons(DNS_PORT);
  return true;
}

// Build a response in-place from the query. mode: 0=sinkhole, 1=NXDOMAIN,
// 2=REFUSED. For sinkhole, answer with 0.0.0.0 (A) or :: (AAAA).
static int buildBlockResponse(uint8_t* buf, int qEnd, uint16_t qtype, int mode) {
  buf[2] = 0x80 | (buf[2] & 0x01);  // QR=1, keep RD
  uint8_t rcode = (mode == 1) ? 3 : (mode == 2) ? 5 : 0;
  buf[3] = 0x80 | rcode;            // RA=1 + rcode
  bool answer = (mode == 0) && (qtype == 1 || qtype == 28);
  uint16_t ancount = answer ? 1 : 0;
  buf[6] = ancount >> 8; buf[7] = ancount & 0xFF;  // ANCOUNT
  buf[8] = 0; buf[9] = 0;                           // NSCOUNT
  buf[10] = 0; buf[11] = 0;                          // ARCOUNT
  int pos = qEnd;
  if (answer) {
    buf[pos++] = 0xC0; buf[pos++] = 0x0C;           // name -> offset 12
    buf[pos++] = 0x00; buf[pos++] = (qtype == 28) ? 28 : 1;  // type
    buf[pos++] = 0x00; buf[pos++] = 0x01;           // class IN
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 60;  // TTL=60
    uint16_t rdlen = (qtype == 28) ? 16 : 4;
    buf[pos++] = 0; buf[pos++] = rdlen;             // RDLENGTH
    for (int i = 0; i < rdlen; i++) buf[pos++] = 0; // 0.0.0.0 / ::
  }
  return pos;
}

static int allocPending(uint16_t origId, const struct sockaddr_in* cli, uint16_t* sentId) {
  for (int i = 0; i < MAX_PENDING; i++) {
    if (!gPending[i].inUse) {
      gPending[i].inUse = true;
      gPending[i].origId = origId;
      gPending[i].cli = *cli;
      gPending[i].ts = millis();
      uint16_t id = ((uint16_t)gNonce++ << 8) | (uint8_t)i;
      gPending[i].sentId = id;
      *sentId = id;
      return i;
    }
  }
  return -1;
}

static void expirePending() {
  uint32_t now = millis();
  for (int i = 0; i < MAX_PENDING; i++)
    if (gPending[i].inUse && (now - gPending[i].ts) > PENDING_TTL_MS)
      gPending[i].inUse = false;
}

static void handleClient() {
  uint8_t buf[BUF_SIZE];
  struct sockaddr_in from;
  socklen_t fl = sizeof(from);
  int n = recvfrom(gListenSock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
  if (n < 12) return;
  uint32_t ip = ntohl(from.sin_addr.s_addr);
  char name[STATS_DOMAIN_LEN];
  uint16_t qtype = 0;
  int qEnd = parseQuestion(buf, n, name, sizeof(name), &qtype);
  if (qEnd < 0) return;

  // Banned client -> REFUSED.
  if (statsIsBanned(ip)) {
    int rn = buildBlockResponse(buf, qEnd, qtype, 2);
    sendto(gListenSock, buf, rn, 0, (struct sockaddr*)&from, fl);
    statsRecord(ip, name, qtype, QR_BLOCKED);
    return;
  }

  // Blocked domain -> sinkhole or NXDOMAIN.
  if (gConfig.blockingEnabled && (qtype == 1 || qtype == 28 || qtype == 65) &&
      blocklistIsBlocked(name)) {
    int rn = buildBlockResponse(buf, qEnd, qtype, gConfig.blockMode ? 1 : 0);
    sendto(gListenSock, buf, rn, 0, (struct sockaddr*)&from, fl);
    statsRecord(ip, name, qtype, QR_BLOCKED);
    return;
  }

  // Forward to upstream.
  struct sockaddr_in up;
  if (!resolveUpstream(&up)) return;
  uint16_t sentId;
  if (allocPending((buf[0] << 8) | buf[1], &from, &sentId) < 0) return;  // table full, drop
  buf[0] = sentId >> 8; buf[1] = sentId & 0xFF;
  sendto(gUpSock, buf, n, 0, (struct sockaddr*)&up, sizeof(up));
  statsRecord(ip, name, qtype, QR_FORWARDED);
}

static void handleUpstream() {
  uint8_t buf[BUF_SIZE];
  struct sockaddr_in from;
  socklen_t fl = sizeof(from);
  int n = recvfrom(gUpSock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fl);
  if (n < 2) return;
  uint16_t id = (buf[0] << 8) | buf[1];
  int slot = id & 0xFF;
  if (slot >= MAX_PENDING || !gPending[slot].inUse || gPending[slot].sentId != id) return;
  buf[0] = gPending[slot].origId >> 8;
  buf[1] = gPending[slot].origId & 0xFF;
  sendto(gListenSock, buf, n, 0, (struct sockaddr*)&gPending[slot].cli,
         sizeof(gPending[slot].cli));
  gPending[slot].inUse = false;
}

static void dnsTask(void*) {
  for (;;) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(gListenSock, &rfds);
    FD_SET(gUpSock, &rfds);
    int maxfd = (gListenSock > gUpSock ? gListenSock : gUpSock) + 1;
    struct timeval tv = { 1, 0 };
    int r = select(maxfd, &rfds, nullptr, nullptr, &tv);
    if (r > 0) {
      if (FD_ISSET(gListenSock, &rfds)) handleClient();
      if (FD_ISSET(gUpSock, &rfds)) handleUpstream();
    }
    expirePending();
  }
}

void dnsServerStart() {
  memset(gPending, 0, sizeof(gPending));
  gListenSock = socket(AF_INET, SOCK_DGRAM, 0);
  gUpSock = socket(AF_INET, SOCK_DGRAM, 0);
  if (gListenSock < 0 || gUpSock < 0) {
    Serial.println("[dns] socket() failed");
    return;
  }
  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(DNS_PORT);
  if (bind(gListenSock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    Serial.println("[dns] bind :53 failed");
    return;
  }
  // Pin to core 1 so DNS latency is isolated from the async web stack (core 0).
  xTaskCreatePinnedToCore(dnsTask, "dns", 8192, nullptr, 5, nullptr, 1);
  Serial.println("[dns] server started on :53");
}
