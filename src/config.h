#pragma once
#include <Arduino.h>

// Persistent configuration, stored in NVS via the Preferences library.
struct Config {
  // WiFi
  String wifiSsid;
  String wifiPass;

  // Identity / network
  String hostname;        // mDNS name -> <hostname>.local
  String upstream1;       // primary upstream DNS resolver
  String upstream2;       // secondary upstream DNS resolver

  // Blocking
  uint8_t blockMode;      // 0 = answer 0.0.0.0 / ::, 1 = NXDOMAIN
  bool blockingEnabled;   // master on/off switch

  // Blocklist auto-update
  String blocklistUrl;    // URL of a pre-compiled .bin (ADBK format)
  uint16_t updateHours;   // auto-update interval in hours (0 = disabled)

  // Dashboard auth (HTTP Basic)
  String webUser;
  String webPass;

  void loadDefaults();
};

extern Config gConfig;

// Load config from NVS (filling defaults for anything missing).
void configLoad();
// Persist the current gConfig to NVS.
void configSave();
// Clear WiFi credentials (used by the "forget wifi" action).
void configForgetWifi();
