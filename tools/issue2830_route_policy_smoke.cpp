#include "client/platforms/windows/daemon/windowsroutecapturepolicy.h"

#include <cassert>
#include <cstring>

namespace {
constexpr unsigned long long kVpnLuid = 42;
constexpr unsigned long long kLanLuid = 7;
constexpr ULONG kMonitorMetric = 0x5e72;

MIB_IPFORWARD_ROW2 baseIpv4Route() {
  MIB_IPFORWARD_ROW2 row;
  InitializeIpForwardEntry(&row);
  row.InterfaceLuid.Value = kLanLuid;
  row.DestinationPrefix.Prefix.si_family = AF_INET;
  row.DestinationPrefix.PrefixLength = 24;
  row.NextHop.si_family = AF_INET;
  row.Protocol = MIB_IPPROTO_NETMGMT;
  row.Metric = 10;
  return row;
}
}

int main() {
  {
    auto row = baseIpv4Route();
    row.NextHop.Ipv4.sin_addr.s_addr = htonl(0xc0a80101);
    assert(!WindowsRouteCapturePolicy::isOnLinkRoute(&row));
    assert(WindowsRouteCapturePolicy::shouldCaptureRoute(
        &row, kVpnLuid, false, kMonitorMetric));
  }

  {
    auto row = baseIpv4Route();
    row.NextHop.Ipv4.sin_addr.s_addr = 0;
    assert(WindowsRouteCapturePolicy::isOnLinkRoute(&row));
    assert(!WindowsRouteCapturePolicy::shouldCaptureRoute(
        &row, kVpnLuid, false, kMonitorMetric));
  }

  {
    auto row = baseIpv4Route();
    row.NextHop.si_family = AF_UNSPEC;
    assert(WindowsRouteCapturePolicy::isOnLinkRoute(&row));
    assert(!WindowsRouteCapturePolicy::shouldCaptureRoute(
        &row, kVpnLuid, false, kMonitorMetric));
  }

  {
    auto row = baseIpv4Route();
    row.DestinationPrefix.PrefixLength = 0;
    row.NextHop.Ipv4.sin_addr.s_addr = htonl(0xc0a80101);
    assert(!WindowsRouteCapturePolicy::shouldCaptureRoute(
        &row, kVpnLuid, false, kMonitorMetric));
  }

  {
    auto row = baseIpv4Route();
    row.InterfaceLuid.Value = kVpnLuid;
    row.NextHop.Ipv4.sin_addr.s_addr = htonl(0xc0a80101);
    assert(!WindowsRouteCapturePolicy::shouldCaptureRoute(
        &row, kVpnLuid, false, kMonitorMetric));
  }

  return 0;
}
