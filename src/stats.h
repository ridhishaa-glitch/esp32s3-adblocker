#pragma once
#include <Arduino.h>

// ---- Rolling query statistics, per-client tracking and a query log. ----
// Log + histogram live in PSRAM (allocated at init) to keep internal RAM free.

#define STATS_MAX_CLIENTS   96
#define STATS_LOG_SIZE      2000   // ring buffer of recent queries
#define STATS_DOMAIN_LEN    80
#define STATS_HIST_BUCKETS  24     // one bucket per hour, rolling 24h

enum QueryResult : uint8_t {
  QR_FORWARDED = 0,
  QR_BLOCKED   = 1,
  QR_CACHED    = 2,
};

struct ClientStat {
  uint32_t ip;        // IPv4 as network-order-independent host uint32
  uint32_t total;
  uint32_t blocked;
  uint32_t lastSeen;  // epoch seconds (or millis/1000 fallback)
  bool banned;
  bool used;
};

struct LogEntry {
  uint32_t ts;        // epoch seconds (or 0 if unknown)
  uint32_t ip;
  uint8_t  result;    // QueryResult
  uint8_t  qtype;     // DNS qtype (1=A, 28=AAAA, ...)
  char     domain[STATS_DOMAIN_LEN];
};

struct HistBucket {
  uint32_t hourTag;   // epoch / 3600 this bucket represents
  uint32_t total;
  uint32_t blocked;
};

void statsInit();
void statsRecord(uint32_t ip, const char* domain, uint8_t qtype, QueryResult result);

// Counters
uint32_t statsTotal();
uint32_t statsBlocked();
uint32_t statsForwarded();
uint32_t statsCached();
uint32_t statsUptimeSec();

// Clients
int statsClientCount();
const ClientStat* statsClients();
bool statsIsBanned(uint32_t ip);
void statsSetBan(uint32_t ip, bool banned);
void statsResetCounters();

// Log (returns up to `max` most-recent entries newest-first into out[])
int statsRecentLog(LogEntry* out, int max);

// Histogram (fills up to STATS_HIST_BUCKETS buckets oldest-first, returns count)
int statsHistogram(HistBucket* out);

// Top blocked domains (fills name/count, returns count up to `max`)
struct TopDomain { char domain[STATS_DOMAIN_LEN]; uint32_t count; };
int statsTopBlocked(TopDomain* out, int max);
