#include <Arduino.h>
#include <WiFi.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <time.h>

#include "config.h"
#include "stats.h"
#include "blocklist.h"
#include "dns_server.h"
#include "web_server.h"
#include "updater.h"
#include "wifi_portal.h"

// Deferred reboot request (set by web endpoints, honored in loop()).
volatile uint32_t gRebootAt = 0;

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n=== ESP32-S3 AdBlock " ADBLOCK_FW_VERSION " ===");

  if (psramFound()) {
    Serial.printf("[boot] PSRAM: %u bytes\n", (unsigned)ESP.getPsramSize());
  } else {
    Serial.println("[boot] WARNING: PSRAM not found - large blocklists will fail");
  }

  if (!LittleFS.begin(true)) {   // format on first boot / corruption
    Serial.println("[boot] LittleFS mount failed");
  } else {
    Serial.printf("[boot] LittleFS: %u/%u bytes used\n",
                  (unsigned)LittleFS.usedBytes(), (unsigned)LittleFS.totalBytes());
  }

  configLoad();
  statsInit();

  if (gConfig.webUser == "admin" && gConfig.webPass == "admin") {
    Serial.println("[boot] WARNING: default dashboard login admin/admin — "
                   "change it in Settings; this device sees all DNS traffic.");
  }

  if (!wifiBegin()) {
    wifiRunPortal();             // never returns; reboots after setup
  }

  // Real-time clock for log timestamps and update scheduling.
  configTime(0, 0, "pool.ntp.org", "time.google.com");

  if (MDNS.begin(gConfig.hostname.c_str())) {
    MDNS.addService("http", "tcp", 80);
    Serial.printf("[boot] mDNS: http://%s.local\n", gConfig.hostname.c_str());
  }

  uint32_t loaded = blocklistLoadMain();
  blocklistLoadCustom();
  Serial.printf("[boot] blocklist: %u domains (%u KB PSRAM)\n",
                loaded, (unsigned)(blocklistBytesUsed() / 1024));

  dnsServerStart();
  webServerStart();
  updaterInit();

  Serial.println("[boot] ready");
}

void loop() {
  updaterLoop();

  if (gRebootAt && millis() >= gRebootAt) {
    Serial.println("[sys] rebooting");
    delay(100);
    ESP.restart();
  }

  delay(50);
}
