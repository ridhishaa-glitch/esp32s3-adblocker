#pragma once
#include <Arduino.h>
#include <vector>

// Compiled blocklist stored on LittleFS as /blocklist.bin in "ADBK" format:
//   magic[4]="ADBK", ver(1)=1, hashBits(1)=40, reserved(2),
//   count(4, LE), then count * 5-byte little-endian FNV-1a/40 hashes, sorted asc.
// Loaded into PSRAM (packed, 5 bytes/entry) and binary-searched.

#define ADBK_MAGIC0 'A'
#define ADBK_MAGIC1 'D'
#define ADBK_MAGIC2 'B'
#define ADBK_MAGIC3 'K'
#define BLOCKLIST_PATH   "/blocklist.bin"
#define CUSTOM_BLOCK_PATH "/custom_block.txt"
#define CUSTOM_ALLOW_PATH "/custom_allow.txt"

// 40-bit FNV-1a hash of a (lowercased) domain. Must match tools/build_blocklist.py.
uint64_t fnv40(const char* s, size_t len);

void blocklistInit();
// (Re)load the main compiled table from LittleFS. Returns entry count (0 on fail).
uint32_t blocklistLoadMain();
// Load custom block/allow lists from LittleFS into memory.
void blocklistLoadCustom();

// Decide whether a domain (and its parent suffixes) is blocked.
// Allowlist entries override both custom and compiled blocks.
bool blocklistIsBlocked(const char* domain);

uint32_t blocklistCount();        // compiled entries loaded in PSRAM
size_t   blocklistBytesUsed();    // PSRAM bytes used by the compiled table

// Custom list management (persisted to LittleFS text files).
bool blocklistAddCustom(bool allow, const char* domain);
bool blocklistRemoveCustom(bool allow, const char* domain);
std::vector<String> blocklistCustomList(bool allow);
