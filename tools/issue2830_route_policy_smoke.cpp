#include "client/platforms/windows/daemon/windowsroutecapturepolicy.h"

#include <cassert>
#include <cstring>

namespace {
constexpr unsigned long long kVpnLuid = 42;
constexpr unsigned long long kLanLuid = 7;
constexpr ULONG kMonitorMetric = 0x5e72;

MIB_IPFORWARD_ROW2 baseRoute(ADDRESS_FAMILY family) {
  MIB_IPFORWARD_ROW2 row;
  InitializeIpForwardEntry(&row);
  row.InterfaceLuid.Value = kLanLuid;
  row.DestinationPrefix.Prefix.si_family = family;
  row.DestinationPrefix.PrefixLength = family == AF_INET6 ? 64 : 24;
  row.NextHop.si_family = family;
  row.Protocol = MIB_IPPROTO_NETMGMT;
  row.Metric = 10;
  return row;
}

MIB_IPFORWARD_ROW2 baseIpv4Route() {
  return baseRoute(AF_INET);
}

MIB_IPFORWARD_ROW2 baseIpv6Route() {
  return baseRoute(AF_INET6);
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
    auto row = baseIpv6Route();
    row.NextHop.Ipv6.sin6_addr.u.Byte[0] = 0x20;
    row.NextHop.Ipv6.sin6_addr.u.Byte[1] = 0x01;
    row.NextHop.Ipv6.sin6_addr.u.Byte[2] = 0x0d;
    row.NextHop.Ipv6.sin6_addr.u.Byte[3] = 0xb8;
    row.NextHop.Ipv6.sin6_addr.u.Byte[15] = 0x01;
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
    auto row = baseIpv6Route();
    std::memset(&row.NextHop.Ipv6.sin6_addr, 0,
                sizeof(row.NextHop.Ipv6.sin6_addr));
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

  {
    auto row = baseIpv4Route();
    row.Metric = kMonitorMetric;
    row.NextHop.Ipv4.sin_addr.s_addr = htonl(0xc0a80101);
    assert(WindowsRouteCapturePolicy::isRouteCreatedByMonitor(
        &row, kMonitorMetric));
    assert(!WindowsRouteCapturePolicy::shouldCaptureRoute(
        &row, kVpnLuid, false, kMonitorMetric));
  }

  {
    auto row = baseIpv4Route();
    row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(0);
    row.Metric = kMonitorMetric;
    row.NextHop.Ipv4.sin_addr.s_addr = htonl(0xc0a80101);
    assert(!WindowsRouteCapturePolicy::isRouteCreatedByMonitor(
        &row, kMonitorMetric));
    assert(WindowsRouteCapturePolicy::shouldCaptureRoute(
        &row, kVpnLuid, false, kMonitorMetric));
  }

  {
    auto row = baseIpv4Route();
    row.NextHop.Ipv4.sin_addr.s_addr = htonl(0xc0a80101);
    assert(!WindowsRouteCapturePolicy::shouldCaptureRoute(
        &row, kVpnLuid, true, kMonitorMetric));
  }

  return 0;
}
