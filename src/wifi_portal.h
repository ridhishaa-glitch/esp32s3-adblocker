#pragma once
#include <Arduino.h>

// Returns true if we connected to WiFi using stored credentials.
bool wifiBegin();

// Starts a SoftAP captive portal for first-time setup. Does not return
// (reboots once the user submits credentials).
void wifiRunPortal();
