#include "config.h"
#include <Preferences.h>

Config gConfig;

static Preferences prefs;
static const char* NS = "adblock";

void Config::loadDefaults() {
  wifiSsid = "";
  wifiPass = "";
  hostname = "adblock";
  upstream1 = "1.1.1.1";
  upstream2 = "8.8.8.8";
  blockMode = 0;
  blockingEnabled = true;
  // Default to this project's auto-built rolling release (StevenBlack + Hagezi
  // light). Override from the dashboard or setup portal.
  blocklistUrl = "https://github.com/ridhishaa-glitch/esp32s3-adblocker/"
                 "releases/download/blocklist-latest/blocklist.bin";
  updateHours = 24;
  webUser = "admin";
  webPass = "admin";
}

void configLoad() {
  gConfig.loadDefaults();
  prefs.begin(NS, true);  // read-only
  gConfig.wifiSsid   = prefs.getString("ssid", gConfig.wifiSsid);
  gConfig.wifiPass   = prefs.getString("pass", gConfig.wifiPass);
  gConfig.hostname   = prefs.getString("host", gConfig.hostname);
  gConfig.upstream1  = prefs.getString("up1", gConfig.upstream1);
  gConfig.upstream2  = prefs.getString("up2", gConfig.upstream2);
  gConfig.blockMode  = prefs.getUChar("bmode", gConfig.blockMode);
  gConfig.blockingEnabled = prefs.getBool("benab", gConfig.blockingEnabled);
  gConfig.blocklistUrl = prefs.getString("blurl", gConfig.blocklistUrl);
  gConfig.updateHours = prefs.getUShort("uphrs", gConfig.updateHours);
  gConfig.webUser    = prefs.getString("wuser", gConfig.webUser);
  gConfig.webPass    = prefs.getString("wpass", gConfig.webPass);
  prefs.end();
}

void configSave() {
  prefs.begin(NS, false);  // read-write
  prefs.putString("ssid", gConfig.wifiSsid);
  prefs.putString("pass", gConfig.wifiPass);
  prefs.putString("host", gConfig.hostname);
  prefs.putString("up1", gConfig.upstream1);
  prefs.putString("up2", gConfig.upstream2);
  prefs.putUChar("bmode", gConfig.blockMode);
  prefs.putBool("benab", gConfig.blockingEnabled);
  prefs.putString("blurl", gConfig.blocklistUrl);
  prefs.putUShort("uphrs", gConfig.updateHours);
  prefs.putString("wuser", gConfig.webUser);
  prefs.putString("wpass", gConfig.webPass);
  prefs.end();
}

void configForgetWifi() {
  prefs.begin(NS, false);
  prefs.remove("ssid");
  prefs.remove("pass");
  prefs.end();
  gConfig.wifiSsid = "";
  gConfig.wifiPass = "";
}
