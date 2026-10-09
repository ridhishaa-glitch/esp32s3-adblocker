#pragma once
#include <Arduino.h>

// UDP DNS proxy/sinkhole running in its own FreeRTOS task.
// - Listens on :53 for client queries.
// - Blocks (sinkhole 0.0.0.0/:: or NXDOMAIN) domains on the blocklist.
// - Forwards everything else to the configured upstream resolver and relays
//   the reply (non-blocking, via a pending-query table keyed by DNS id).

void dnsServerStart();

// Format a host-order IPv4 uint32 as "a.b.c.d".
String ipToStr(uint32_t hostIp);
