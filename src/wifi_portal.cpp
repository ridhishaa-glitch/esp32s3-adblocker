#include "wifi_portal.h"
#include "config.h"
#include <WiFi.h>
#include <DNSServer.h>
#include <ESPAsyncWebServer.h>

bool wifiBegin() {
  if (gConfig.wifiSsid.isEmpty()) return false;
  WiFi.mode(WIFI_STA);
  WiFi.setHostname(gConfig.hostname.c_str());
  WiFi.begin(gConfig.wifiSsid.c_str(), gConfig.wifiPass.c_str());
  Serial.printf("[wifi] connecting to %s", gConfig.wifiSsid.c_str());
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 20000) {
    delay(300);
    Serial.print(".");
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("[wifi] connected, IP %s\n", WiFi.localIP().toString().c_str());
    return true;
  }
  Serial.println("[wifi] connect failed");
  return false;
}

static String portalPage() {
  int n = WiFi.scanNetworks();
  String opts;
  for (int i = 0; i < n; i++) {
    String ssid = WiFi.SSID(i);
    opts += "<option value='" + ssid + "'>" + ssid + " (" + WiFi.RSSI(i) + "dBm)</option>";
  }
  String p = F("<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>AdBlock Setup</title><style>body{font:15px system-ui;background:#0e1116;color:#e6edf3;"
    "max-width:420px;margin:30px auto;padding:0 16px}input,select{width:100%;padding:10px;margin:6px 0 12px;"
    "background:#0d1117;color:#e6edf3;border:1px solid #232b36;border-radius:8px;box-sizing:border-box}"
    "button{width:100%;padding:12px;background:#3fb6ff;color:#042033;border:0;border-radius:8px;"
    "font-weight:600;font-size:15px}label{color:#8b98a9;font-size:13px}h1{font-size:19px}</style>"
    "<h1>ESP32-S3 AdBlock setup</h1><form method=POST action=/save>"
    "<label>WiFi network</label><select name=ssid>");
  p += opts;
  p += F("</select><label>WiFi password</label><input name=pass type=password>"
    "<label>Upstream DNS</label><input name=upstream1 value='1.1.1.1'>"
    "<label>Blocklist .bin URL (optional)</label><input name=blocklistUrl placeholder='https://...'>"
    "<button type=submit>Save &amp; reboot</button></form>"
    "<p style='color:#8b98a9;font-size:12px'>The device will restart and join your network. "
    "Then point your router's DNS (or a client) at its IP.</p>");
  return p;
}

void wifiRunPortal() {
  Serial.println("[wifi] starting setup portal");
  WiFi.mode(WIFI_AP);
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char ap[32];
  snprintf(ap, sizeof(ap), "ESP32S3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  Serial.printf("[wifi] AP '%s' at %s\n", ap, apIP.toString().c_str());

  static DNSServer dns;
  dns.start(53, "*", apIP);        // captive-portal catch-all
  static AsyncWebServer portal(80);

  portal.on("/", HTTP_GET, [](AsyncWebServerRequest* r){ r->send(200, "text/html", portalPage()); });
  portal.on("/save", HTTP_POST, [](AsyncWebServerRequest* r){
    auto get = [&](const char* k){ return r->hasParam(k, true) ? r->getParam(k, true)->value() : String(); };
    gConfig.wifiSsid = get("ssid");
    gConfig.wifiPass = get("pass");
    if (get("upstream1").length()) gConfig.upstream1 = get("upstream1");
    if (get("blocklistUrl").length()) gConfig.blocklistUrl = get("blocklistUrl");
    configSave();
    r->send(200, "text/html", "<meta http-equiv=refresh content='8;url=/'>"
      "<body style='font:15px system-ui;background:#0e1116;color:#e6edf3;text-align:center;padding-top:60px'>"
      "Saved. Rebooting and joining your network...");
    delay(800);
    ESP.restart();
  });
  portal.onNotFound([](AsyncWebServerRequest* r){ r->redirect("/"); });
  portal.begin();

  for (;;) { dns.processNextRequest(); delay(10); }
}
