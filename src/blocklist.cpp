#include "blocklist.h"
#include <LittleFS.h>
#include <algorithm>

// ---- Compiled table (packed 5-byte entries in PSRAM) ----
static uint8_t* gHashes = nullptr;
static uint32_t gCount = 0;

// ---- Custom lists (sorted hash vectors held in RAM) ----
static std::vector<uint64_t> gBlockHashes;
static std::vector<uint64_t> gAllowHashes;

uint64_t fnv40(const char* s, size_t len) {
  uint64_t h = 0xcbf29ce484222325ULL;          // FNV-1a 64 offset basis
  for (size_t i = 0; i < len; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') c += 32;          // lowercase
    h ^= (uint8_t)c;
    h *= 0x100000001b3ULL;                      // FNV prime
  }
  return h & 0xFFFFFFFFFFULL;                    // mask to 40 bits
}

static inline uint64_t getPacked(uint32_t i) {
  const uint8_t* p = gHashes + (size_t)i * 5;
  return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
         ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32);
}

static bool mainContains(uint64_t h) {
  if (!gHashes || gCount == 0) return false;
  uint32_t lo = 0, hi = gCount;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    uint64_t v = getPacked(mid);
    if (v < h) lo = mid + 1;
    else hi = mid;
  }
  return lo < gCount && getPacked(lo) == h;
}

static bool vecContains(const std::vector<uint64_t>& v, uint64_t h) {
  return std::binary_search(v.begin(), v.end(), h);
}

void blocklistInit() {
  blocklistLoadMain();
  blocklistLoadCustom();
}

uint32_t blocklistLoadMain() {
  if (gHashes) { free(gHashes); gHashes = nullptr; }
  gCount = 0;
  File f = LittleFS.open(BLOCKLIST_PATH, "r");
  if (!f) return 0;
  uint8_t hdr[12];
  if (f.read(hdr, 12) != 12) { f.close(); return 0; }
  if (hdr[0] != ADBK_MAGIC0 || hdr[1] != ADBK_MAGIC1 ||
      hdr[2] != ADBK_MAGIC2 || hdr[3] != ADBK_MAGIC3 || hdr[4] != 1 || hdr[5] != 40) {
    f.close(); return 0;
  }
  uint32_t count = (uint32_t)hdr[8] | ((uint32_t)hdr[9] << 8) |
                   ((uint32_t)hdr[10] << 16) | ((uint32_t)hdr[11] << 24);
  size_t bytes = (size_t)count * 5;
  if (count == 0 || bytes > 7u * 1024 * 1024) { f.close(); return 0; }  // sanity cap
  gHashes = (uint8_t*)ps_malloc(bytes);
  if (!gHashes) gHashes = (uint8_t*)malloc(bytes);
  if (!gHashes) { f.close(); return 0; }
  size_t got = f.read(gHashes, bytes);
  f.close();
  if (got != bytes) { free(gHashes); gHashes = nullptr; return 0; }
  gCount = count;
  return gCount;
}

static void loadVecFromFile(const char* path, std::vector<uint64_t>& v) {
  v.clear();
  File f = LittleFS.open(path, "r");
  if (!f) return;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() == 0 || line.startsWith("#")) continue;
    line.toLowerCase();
    v.push_back(fnv40(line.c_str(), line.length()));
  }
  f.close();
  std::sort(v.begin(), v.end());
}

void blocklistLoadCustom() {
  loadVecFromFile(CUSTOM_BLOCK_PATH, gBlockHashes);
  loadVecFromFile(CUSTOM_ALLOW_PATH, gAllowHashes);
}

// Fill `out` with hashes for the domain and each parent suffix (>= 2 labels).
static int suffixHashes(const char* domain, uint64_t* out, int maxOut) {
  int len = strlen(domain);
  if (len <= 0) return 0;
  // Trim a trailing dot if present.
  if (domain[len - 1] == '.') len--;
  int n = 0;
  int start = 0;
  while (n < maxOut) {
    int labels = 0;
    for (int i = start; i < len; i++) if (domain[i] == '.') labels++;
    if (labels < 1) break;  // fewer than 2 labels remaining -> stop (skip bare TLD)
    out[n++] = fnv40(domain + start, len - start);
    // Advance start past the next label boundary.
    int dot = -1;
    for (int i = start; i < len; i++) { if (domain[i] == '.') { dot = i; break; } }
    if (dot < 0) break;
    start = dot + 1;
  }
  return n;
}

bool blocklistIsBlocked(const char* domain) {
  uint64_t h[16];
  int n = suffixHashes(domain, h, 16);
  if (n == 0) return false;
  // Allowlist overrides everything.
  for (int i = 0; i < n; i++) if (vecContains(gAllowHashes, h[i])) return false;
  // Custom block list.
  for (int i = 0; i < n; i++) if (vecContains(gBlockHashes, h[i])) return true;
  // Compiled table.
  for (int i = 0; i < n; i++) if (mainContains(h[i])) return true;
  return false;
}

uint32_t blocklistCount() { return gCount; }
size_t   blocklistBytesUsed() { return (size_t)gCount * 5; }

static String normDomain(const char* domain) {
  String d(domain);
  d.trim();
  d.toLowerCase();
  while (d.endsWith(".")) d.remove(d.length() - 1);
  return d;
}

bool blocklistAddCustom(bool allow, const char* domain) {
  String d = normDomain(domain);
  if (d.length() == 0) return false;
  // Avoid duplicates.
  for (auto& e : blocklistCustomList(allow)) if (e == d) return true;
  File f = LittleFS.open(allow ? CUSTOM_ALLOW_PATH : CUSTOM_BLOCK_PATH, "a");
  if (!f) return false;
  f.print(d); f.print('\n');
  f.close();
  blocklistLoadCustom();
  return true;
}

std::vector<String> blocklistCustomList(bool allow) {
  std::vector<String> out;
  File f = LittleFS.open(allow ? CUSTOM_ALLOW_PATH : CUSTOM_BLOCK_PATH, "r");
  if (!f) return out;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() && !line.startsWith("#")) out.push_back(line);
  }
  f.close();
  return out;
}

bool blocklistRemoveCustom(bool allow, const char* domain) {
  String d = normDomain(domain);
  std::vector<String> list = blocklistCustomList(allow);
  File f = LittleFS.open(allow ? CUSTOM_ALLOW_PATH : CUSTOM_BLOCK_PATH, "w");
  if (!f) return false;
  bool removed = false;
  for (auto& e : list) {
    if (e == d) { removed = true; continue; }
    f.print(e); f.print('\n');
  }
  f.close();
  blocklistLoadCustom();
  return removed;
}
