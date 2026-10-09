#pragma once
#include <Arduino.h>

// Scheduled download of the pre-compiled blocklist (.bin) over HTTP(S) and
// on-demand refresh. Also exposes status for the dashboard.

void updaterInit();
void updaterLoop();            // call from loop(); handles scheduling

void updaterRequestNow();      // trigger a download on the next loop pass
bool updaterBusy();
String updaterLastResult();
uint32_t updaterLastEpoch();   // epoch secs of last successful update (0 if none)

// Performs the download synchronously. Returns true on success.
bool updaterDownloadBlocklist(String& result);
