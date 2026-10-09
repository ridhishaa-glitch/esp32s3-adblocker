#include "web_server.h"
#include "web_ui.h"
#include "config.h"
#include "stats.h"
#include "blocklist.h"
#include "updater.h"
#include "dns_server.h"
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <Update.h>
#include <LittleFS.h>

extern volatile uint32_t gRebootAt;   // defined in main.cpp

static AsyncWebServer server(80);

// Parse "a.b.c.d" into a host-order uint32 (matches ipToStr / stats keys).
static uint32_t parseIp(const String& s) {
  int p[4] = {0,0,0,0}, idx = 0;
  for (int i = 0; i < s.length() && idx < 4; i++) {
    char c = s[i];
    if (c == '.') idx++;
    else if (c >= '0' && c <= '9') p[idx] = p[idx] * 10 + (c - '0');
  }
  return ((uint32_t)(p[0]&0xFF) << 24) | ((p[1]&0xFF) << 16) |
         ((p[2]&0xFF) << 8) | (p[3]&0xFF);
}

// Gate for all state-changing endpoints: CSRF header + HTTP Basic auth.
static bool guard(AsyncWebServerRequest* req) {
  if (!req->hasHeader("X-Requested-With")) {
    req->send(403, "text/plain", "missing X-Requested-With");
    return false;
  }
  if (!req->authenticate(gConfig.webUser.c_str(), gConfig.webPass.c_str())) {
    req->requestAuthentication();
    return false;
  }
  return true;
}

static String param(AsyncWebServerRequest* req, const char* name) {
  if (req->hasParam(name, true)) return req->getParam(name, true)->value();
  if (req->hasParam(name)) return req->getParam(name)->value();
  return String();
}

static void sendJson(AsyncWebServerRequest* req, JsonDocument& doc) {
  String out;
  serializeJson(doc, out);
  req->send(200, "application/json", out);
}

static void handleStats(AsyncWebServerRequest* req) {
  JsonDocument doc;
  uint32_t total = statsTotal(), blocked = statsBlocked();
  doc["total"] = total;
  doc["blocked"] = blocked;
  doc["forwarded"] = statsForwarded();
  doc["cached"] = statsCached();
  doc["blockedPct"] = total ? (100.0 * blocked / total) : 0.0;
  doc["blocklistCount"] = blocklistCount();
  doc["clients"] = statsClientCount();
  doc["uptime"] = statsUptimeSec();
  doc["blockingEnabled"] = gConfig.blockingEnabled;
  doc["fw"] = ADBLOCK_FW_VERSION;
  doc["heap"] = ESP.getFreeHeap();
  doc["psramFree"] = ESP.getFreePsram();
  doc["ip"] = WiFi.localIP().toString();
  sendJson(req, doc);
}

static void handleClients(AsyncWebServerRequest* req) {
  JsonDocument doc;
  JsonArray arr = doc.to<JsonArray>();
  const ClientStat* cs = statsClients();
  for (int i = 0; i < STATS_MAX_CLIENTS; i++) {
    if (!cs[i].used) continue;
    JsonObject o = arr.add<JsonObject>();
    o["ip"] = ipToStr(cs[i].ip);
    o["total"] = cs[i].total;
    o["blocked"] = cs[i].blocked;
    o["lastSeen"] = cs[i].lastSeen;
    o["banned"] = cs[i].banned;
  }
  sendJson(req, doc);
}

static void handleLog(AsyncWebServerRequest* req) {
  int n = 100;
  if (req->hasParam("n")) n = req->getParam("n")->value().toInt();
  if (n < 1) n = 1; if (n > 500) n = 500;
  LogEntry* buf = (LogEntry*)malloc(sizeof(LogEntry) * n);
  if (!buf) { req->send(500, "text/plain", "oom"); return; }
  int got = statsRecentLog(buf, n);
  JsonDocument doc;
  JsonArray arr = doc.to<JsonArray>();
  for (int i = 0; i < got; i++) {
    JsonObject o = arr.add<JsonObject>();
    o["ts"] = buf[i].ts;
    o["ip"] = ipToStr(buf[i].ip);
    o["domain"] = buf[i].domain;
    o["qtype"] = buf[i].qtype;
    o["result"] = buf[i].result;
  }
  free(buf);
  sendJson(req, doc);
}

static void handleHist(AsyncWebServerRequest* req) {
  HistBucket hb[STATS_HIST_BUCKETS];
  int n = statsHistogram(hb);
  JsonDocument doc;
  JsonArray arr = doc.to<JsonArray>();
  for (int i = 0; i < n; i++) {
    JsonObject o = arr.add<JsonObject>();
    o["total"] = hb[i].total;
    o["blocked"] = hb[i].blocked;
  }
  sendJson(req, doc);
}

static void handleTop(AsyncWebServerRequest* req) {
  int n = 20;
  if (req->hasParam("n")) n = req->getParam("n")->value().toInt();
  if (n < 1) n = 1; if (n > 100) n = 100;
  TopDomain* buf = (TopDomain*)malloc(sizeof(TopDomain) * n);
  if (!buf) { req->send(500, "text/plain", "oom"); return; }
  int got = statsTopBlocked(buf, n);
  JsonDocument doc;
  JsonArray arr = doc.to<JsonArray>();
  for (int i = 0; i < got; i++) {
    JsonObject o = arr.add<JsonObject>();
    o["domain"] = buf[i].domain;
    o["count"] = buf[i].count;
  }
  free(buf);
  sendJson(req, doc);
}

static void handleConfigGet(AsyncWebServerRequest* req) {
  JsonDocument doc;
  doc["upstream1"] = gConfig.upstream1;
  doc["upstream2"] = gConfig.upstream2;
  doc["blockMode"] = gConfig.blockMode;
  doc["updateHours"] = gConfig.updateHours;
  doc["hostname"] = gConfig.hostname;
  doc["blocklistUrl"] = gConfig.blocklistUrl;
  doc["webUser"] = gConfig.webUser;
  doc["updateLast"] = updaterLastResult();
  sendJson(req, doc);
}

static void handleConfigPost(AsyncWebServerRequest* req) {
  if (param(req, "upstream1").length()) gConfig.upstream1 = param(req, "upstream1");
  if (param(req, "upstream2").length()) gConfig.upstream2 = param(req, "upstream2");
  if (req->hasParam("blockMode", true)) gConfig.blockMode = param(req, "blockMode").toInt();
  if (req->hasParam("updateHours", true)) gConfig.updateHours = param(req, "updateHours").toInt();
  if (param(req, "hostname").length()) gConfig.hostname = param(req, "hostname");
  if (req->hasParam("blocklistUrl", true)) gConfig.blocklistUrl = param(req, "blocklistUrl");
  if (param(req, "webUser").length()) gConfig.webUser = param(req, "webUser");
  if (param(req, "webPass").length()) gConfig.webPass = param(req, "webPass");
  configSave();
  req->send(200, "application/json", "{\"ok\":true}");
}

static void handleCustomGet(AsyncWebServerRequest* req) {
  bool allow = param(req, "allow") == "1";
  JsonDocument doc;
  JsonArray arr = doc.to<JsonArray>();
  for (auto& d : blocklistCustomList(allow)) arr.add(d);
  sendJson(req, doc);
}

static void handleCustomPost(AsyncWebServerRequest* req) {
  bool allow = param(req, "allow") == "1";
  String action = param(req, "action");
  String domain = param(req, "domain");
  bool ok = (action == "remove") ? blocklistRemoveCustom(allow, domain.c_str())
                                  : blocklistAddCustom(allow, domain.c_str());
  req->send(ok ? 200 : 400, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
}

static void scheduleReboot() { gRebootAt = millis() + 600; }

// Validate an on-disk ADBK file (header + exact size). Fills `count`.
static bool validateAdbk(const char* path, uint32_t& count) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  uint8_t h[12];
  bool ok = f.read(h, 12) == 12 &&
            h[0]=='A' && h[1]=='D' && h[2]=='B' && h[3]=='K' && h[4]==1 && h[5]==40;
  count = ok ? ((uint32_t)h[8] | ((uint32_t)h[9]<<8) |
                ((uint32_t)h[10]<<16) | ((uint32_t)h[11]<<24)) : 0;
  bool sizeOk = ok && count > 0 && f.size() == 12 + (size_t)count * 5;
  f.close();
  return sizeOk;
}

// State kept across chunks of a dashboard blocklist upload.
static File gBlUpFile;
static bool gBlUpAuth = false;

void webServerStart() {
  server.on("/", HTTP_GET, [](AsyncWebServerRequest* req) {
    req->send_P(200, "text/html", DASHBOARD_HTML);
  });
  server.on("/app.js", HTTP_GET, [](AsyncWebServerRequest* req) {
    AsyncWebServerResponse* r = req->beginResponse_P(200, "application/javascript", DASHBOARD_JS);
    r->addHeader("Cache-Control", "max-age=86400");
    req->send(r);
  });

  // Read-only endpoints (open for viewing).
  server.on("/api/stats", HTTP_GET, handleStats);
  server.on("/api/clients", HTTP_GET, handleClients);
  server.on("/api/log", HTTP_GET, handleLog);
  server.on("/api/hist", HTTP_GET, handleHist);
  server.on("/api/top", HTTP_GET, handleTop);
  server.on("/api/config", HTTP_GET, handleConfigGet);
  server.on("/api/custom", HTTP_GET, handleCustomGet);

  // State-changing endpoints (guarded).
  server.on("/api/config", HTTP_POST, [](AsyncWebServerRequest* r){ if(guard(r)) handleConfigPost(r); });
  server.on("/api/custom", HTTP_POST, [](AsyncWebServerRequest* r){ if(guard(r)) handleCustomPost(r); });
  server.on("/api/toggle", HTTP_POST, [](AsyncWebServerRequest* r){
    if(!guard(r)) return;
    gConfig.blockingEnabled = param(r,"enabled")=="1";
    configSave();
    r->send(200,"application/json","{\"ok\":true}");
  });
  server.on("/api/ban", HTTP_POST, [](AsyncWebServerRequest* r){
    if(!guard(r)) return;
    statsSetBan(parseIp(param(r,"ip")), param(r,"banned")=="1");
    r->send(200,"application/json","{\"ok\":true}");
  });
  server.on("/api/update-now", HTTP_POST, [](AsyncWebServerRequest* r){
    if(!guard(r)) return;
    updaterRequestNow();
    r->send(200,"application/json","{\"ok\":true}");
  });
  server.on("/api/reset-stats", HTTP_POST, [](AsyncWebServerRequest* r){
    if(!guard(r)) return;
    statsResetCounters();
    r->send(200,"application/json","{\"ok\":true}");
  });
  server.on("/api/reboot", HTTP_POST, [](AsyncWebServerRequest* r){
    if(!guard(r)) return;
    r->send(200,"application/json","{\"ok\":true}");
    scheduleReboot();
  });
  server.on("/api/forget-wifi", HTTP_POST, [](AsyncWebServerRequest* r){
    if(!guard(r)) return;
    configForgetWifi();
    r->send(200,"application/json","{\"ok\":true}");
    scheduleReboot();
  });

  // Firmware OTA upload.
  server.on("/update", HTTP_POST,
    [](AsyncWebServerRequest* req){
      bool ok = !Update.hasError();
      req->send(ok ? 200 : 500, "text/plain", ok ? "OK" : "FAIL");
      if (ok) scheduleReboot();
    },
    [](AsyncWebServerRequest* req, String fn, size_t idx, uint8_t* data, size_t len, bool final){
      if (idx == 0) {
        if (!req->authenticate(gConfig.webUser.c_str(), gConfig.webPass.c_str())) {
          req->requestAuthentication();
          return;
        }
        Serial.printf("[ota] start %s\n", fn.c_str());
        Update.begin(UPDATE_SIZE_UNKNOWN);
      }
      if (Update.isRunning()) Update.write(data, len);
      if (final && Update.isRunning()) Update.end(true);
    });

  // Blocklist (.bin) upload from the dashboard.
  server.on("/upload-blocklist", HTTP_POST,
    [](AsyncWebServerRequest* req){
      if (gBlUpFile) gBlUpFile.close();
      if (!gBlUpAuth) { req->requestAuthentication(); return; }
      uint32_t count = 0;
      if (!validateAdbk("/blocklist.tmp", count)) {
        LittleFS.remove("/blocklist.tmp");
        req->send(400, "application/json", "{\"ok\":false,\"error\":\"invalid ADBK file\"}");
        return;
      }
      LittleFS.remove(BLOCKLIST_PATH);
      LittleFS.rename("/blocklist.tmp", BLOCKLIST_PATH);
      uint32_t loaded = blocklistLoadMain();
      String r = "{\"ok\":true,\"domains\":" + String(loaded) + "}";
      req->send(200, "application/json", r);
    },
    [](AsyncWebServerRequest* req, String fn, size_t idx, uint8_t* data, size_t len, bool final){
      if (idx == 0) {
        gBlUpAuth = req->authenticate(gConfig.webUser.c_str(), gConfig.webPass.c_str());
        if (!gBlUpAuth) return;
        gBlUpFile = LittleFS.open("/blocklist.tmp", "w");
      }
      if (gBlUpAuth && gBlUpFile) gBlUpFile.write(data, len);
    });

  server.onNotFound([](AsyncWebServerRequest* req){ req->send(404,"text/plain","not found"); });
  server.begin();
  Serial.println("[web] dashboard on :80");
}
