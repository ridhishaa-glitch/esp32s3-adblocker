#include "updater.h"
#include "config.h"
#include "blocklist.h"
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <LittleFS.h>
#include <time.h>

static bool gRequested = false;
static bool gBusy = false;
static String gLastResult = "never";
static uint32_t gLastEpoch = 0;
static uint32_t gLastAttemptMs = 0;

void updaterInit() {}

void updaterRequestNow() { gRequested = true; }
bool updaterBusy() { return gBusy; }
String updaterLastResult() { return gLastResult; }
uint32_t updaterLastEpoch() { return gLastEpoch; }

static bool validateBin(const char* path, uint32_t& count) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  uint8_t h[12];
  bool ok = f.read(h, 12) == 12 &&
            h[0] == 'A' && h[1] == 'D' && h[2] == 'B' && h[3] == 'K' &&
            h[4] == 1 && h[5] == 40;
  count = ok ? ((uint32_t)h[8] | ((uint32_t)h[9] << 8) |
                ((uint32_t)h[10] << 16) | ((uint32_t)h[11] << 24)) : 0;
  size_t expected = 12 + (size_t)count * 5;
  bool sizeOk = ok && count > 0 && f.size() == expected;
  f.close();
  return sizeOk;
}

bool updaterDownloadBlocklist(String& result) {
  if (gConfig.blocklistUrl.isEmpty()) { result = "no URL configured"; return false; }
  if (WiFi.status() != WL_CONNECTED) { result = "wifi down"; return false; }

  WiFiClientSecure secure;
  secure.setInsecure();           // LAN device; skip cert pinning (documented tradeoff)
  WiFiClient plain;
  bool https = gConfig.blocklistUrl.startsWith("https");

  HTTPClient http;
  http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  bool begun = https ? http.begin(secure, gConfig.blocklistUrl)
                     : http.begin(plain, gConfig.blocklistUrl);
  if (!begun) { result = "begin failed"; return false; }

  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    result = "HTTP " + String(code);
    http.end();
    return false;
  }

  const char* tmp = "/blocklist.tmp";
  File out = LittleFS.open(tmp, "w");
  if (!out) { result = "fs open failed"; http.end(); return false; }

  WiFiClient* stream = http.getStreamPtr();
  uint8_t buf[1024];
  int total = http.getSize();
  int written = 0;
  uint32_t lastData = millis();
  while (http.connected() && (total < 0 || written < total)) {
    size_t avail = stream->available();
    if (avail) {
      int r = stream->readBytes(buf, avail > sizeof(buf) ? sizeof(buf) : avail);
      if (r > 0) { out.write(buf, r); written += r; lastData = millis(); }
    } else {
      if (millis() - lastData > 15000) break;   // stall timeout
      delay(5);
    }
  }
  out.close();
  http.end();

  uint32_t count = 0;
  if (!validateBin(tmp, count)) {
    LittleFS.remove(tmp);
    result = "invalid/short download (" + String(written) + " bytes)";
    return false;
  }

  LittleFS.remove(BLOCKLIST_PATH);
  if (!LittleFS.rename(tmp, BLOCKLIST_PATH)) {
    result = "rename failed";
    return false;
  }
  uint32_t loaded = blocklistLoadMain();
  time_t now = time(nullptr);
  gLastEpoch = (now > 1700000000) ? (uint32_t)now : 0;
  result = "ok: " + String(loaded) + " domains";
  return true;
}

void updaterLoop() {
  bool due = false;
  if (gConfig.updateHours > 0) {
    uint32_t intervalMs = (uint32_t)gConfig.updateHours * 3600UL * 1000UL;
    // First attempt ~30s after boot if we have never updated.
    if (gLastAttemptMs == 0 && millis() > 30000) due = true;
    else if (gLastAttemptMs != 0 && millis() - gLastAttemptMs >= intervalMs) due = true;
  }
  if (!gRequested && !due) return;

  gRequested = false;
  gLastAttemptMs = millis();
  gBusy = true;
  String r;
  bool ok = updaterDownloadBlocklist(r);
  gLastResult = (ok ? "" : "error: ") + r;
  gBusy = false;
  Serial.printf("[update] %s\n", gLastResult.c_str());
}
