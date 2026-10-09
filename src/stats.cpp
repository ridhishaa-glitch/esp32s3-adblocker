#include "stats.h"
#include <time.h>

// ---- Counters ----
static uint32_t gTotal = 0, gBlocked = 0, gForwarded = 0, gCached = 0;
static uint32_t gBootSec = 0;

// ---- Clients ----
static ClientStat gClients[STATS_MAX_CLIENTS];

// ---- Query log (PSRAM ring) ----
static LogEntry* gLog = nullptr;
static int gLogHead = 0;      // next write slot
static int gLogCount = 0;

// ---- Hourly histogram ----
static HistBucket gHist[STATS_HIST_BUCKETS];

// ---- Top blocked domains ----
#define TOP_SLOTS 256
static TopDomain gTop[TOP_SLOTS];
static int gTopUsed = 0;

static uint32_t nowSec() {
  time_t t = time(nullptr);
  if (t > 1700000000) return (uint32_t)t;   // NTP synced (after ~2023-11)
  return millis() / 1000;
}

void statsInit() {
  gBootSec = nowSec();
  memset(gClients, 0, sizeof(gClients));
  memset(gHist, 0, sizeof(gHist));
  memset(gTop, 0, sizeof(gTop));
  gTopUsed = 0;
  gLogHead = gLogCount = 0;
  // Allocate the log in PSRAM; fall back to internal RAM if unavailable.
  size_t bytes = (size_t)STATS_LOG_SIZE * sizeof(LogEntry);
  gLog = (LogEntry*)ps_malloc(bytes);
  if (!gLog) gLog = (LogEntry*)malloc(bytes);
  if (gLog) memset(gLog, 0, bytes);
}

static ClientStat* findClient(uint32_t ip, bool create) {
  ClientStat* freeSlot = nullptr;
  for (int i = 0; i < STATS_MAX_CLIENTS; i++) {
    if (gClients[i].used && gClients[i].ip == ip) return &gClients[i];
    if (!gClients[i].used && !freeSlot) freeSlot = &gClients[i];
  }
  if (create && freeSlot) {
    memset(freeSlot, 0, sizeof(ClientStat));
    freeSlot->ip = ip;
    freeSlot->used = true;
    return freeSlot;
  }
  return create ? nullptr : nullptr;
}

static void histBump(bool blocked) {
  uint32_t hour = nowSec() / 3600;
  int idx = hour % STATS_HIST_BUCKETS;
  if (gHist[idx].hourTag != hour) {
    gHist[idx].hourTag = hour;
    gHist[idx].total = 0;
    gHist[idx].blocked = 0;
  }
  gHist[idx].total++;
  if (blocked) gHist[idx].blocked++;
}

static void topBump(const char* domain) {
  for (int i = 0; i < gTopUsed; i++) {
    if (strncmp(gTop[i].domain, domain, STATS_DOMAIN_LEN) == 0) {
      gTop[i].count++;
      return;
    }
  }
  if (gTopUsed < TOP_SLOTS) {
    strncpy(gTop[gTopUsed].domain, domain, STATS_DOMAIN_LEN - 1);
    gTop[gTopUsed].domain[STATS_DOMAIN_LEN - 1] = 0;
    gTop[gTopUsed].count = 1;
    gTopUsed++;
  }
}

void statsRecord(uint32_t ip, const char* domain, uint8_t qtype, QueryResult result) {
  bool blocked = (result == QR_BLOCKED);
  gTotal++;
  if (blocked) gBlocked++;
  else if (result == QR_CACHED) gCached++;
  else gForwarded++;

  ClientStat* c = findClient(ip, true);
  if (c) {
    c->total++;
    if (blocked) c->blocked++;
    c->lastSeen = nowSec();
  }

  histBump(blocked);
  if (blocked) topBump(domain);

  if (gLog) {
    LogEntry& e = gLog[gLogHead];
    e.ts = nowSec();
    e.ip = ip;
    e.result = (uint8_t)result;
    e.qtype = qtype;
    strncpy(e.domain, domain, STATS_DOMAIN_LEN - 1);
    e.domain[STATS_DOMAIN_LEN - 1] = 0;
    gLogHead = (gLogHead + 1) % STATS_LOG_SIZE;
    if (gLogCount < STATS_LOG_SIZE) gLogCount++;
  }
}

uint32_t statsTotal()     { return gTotal; }
uint32_t statsBlocked()   { return gBlocked; }
uint32_t statsForwarded() { return gForwarded; }
uint32_t statsCached()    { return gCached; }
uint32_t statsUptimeSec() { uint32_t n = nowSec(); return n >= gBootSec ? n - gBootSec : 0; }

int statsClientCount() {
  int n = 0;
  for (int i = 0; i < STATS_MAX_CLIENTS; i++) if (gClients[i].used) n++;
  return n;
}
const ClientStat* statsClients() { return gClients; }

bool statsIsBanned(uint32_t ip) {
  ClientStat* c = findClient(ip, false);
  return c && c->banned;
}

void statsSetBan(uint32_t ip, bool banned) {
  ClientStat* c = findClient(ip, true);
  if (c) c->banned = banned;
}

void statsResetCounters() {
  gTotal = gBlocked = gForwarded = gCached = 0;
  gBootSec = nowSec();
  memset(gHist, 0, sizeof(gHist));
  gTopUsed = 0;
  memset(gTop, 0, sizeof(gTop));
  for (int i = 0; i < STATS_MAX_CLIENTS; i++) {
    gClients[i].total = 0;
    gClients[i].blocked = 0;
  }
  gLogHead = gLogCount = 0;
}

int statsRecentLog(LogEntry* out, int max) {
  int n = 0;
  int idx = (gLogHead - 1 + STATS_LOG_SIZE) % STATS_LOG_SIZE;
  for (int i = 0; i < gLogCount && n < max; i++) {
    out[n++] = gLog[idx];
    idx = (idx - 1 + STATS_LOG_SIZE) % STATS_LOG_SIZE;
  }
  return n;
}

int statsHistogram(HistBucket* out) {
  // Emit buckets ordered oldest -> newest ending at the current hour.
  uint32_t hour = nowSec() / 3600;
  int n = 0;
  for (int i = STATS_HIST_BUCKETS - 1; i >= 0; i--) {
    uint32_t tag = hour - i;
    int idx = tag % STATS_HIST_BUCKETS;
    HistBucket b;
    b.hourTag = tag;
    if (gHist[idx].hourTag == tag) { b.total = gHist[idx].total; b.blocked = gHist[idx].blocked; }
    else { b.total = 0; b.blocked = 0; }
    out[n++] = b;
  }
  return n;
}

int statsTopBlocked(TopDomain* out, int max) {
  // Simple selection of the top `max` by count.
  bool taken[TOP_SLOTS] = {false};
  int n = 0;
  while (n < max) {
    int best = -1;
    for (int i = 0; i < gTopUsed; i++) {
      if (taken[i]) continue;
      if (best < 0 || gTop[i].count > gTop[best].count) best = i;
    }
    if (best < 0 || gTop[best].count == 0) break;
    taken[best] = true;
    out[n++] = gTop[best];
  }
  return n;
}
