/* Copyright (c) 2014 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef RAMCLOUD_ARPCACHE_H
#define RAMCLOUD_ARPCACHE_H

#include <net/if.h>
#include "Syscall.h"
#include "Dispatch.h"
#include "Tub.h"
#include "Driver.h"
#include "EthernetUtil.h"

namespace RAMCloud {

using namespace EthernetUtil; //NOLINT

/**
 * ArpCache provides a local table for IP-MAC translations. This table is
 * basically a cache to resolve MAC address corresponding to an IP address.
 * Layer 3 drivers codes keep an instance of this ArpCache objects for the
 * purpose of fast IP-MAC resolutions.
 */
class ArpCache {
  public:
    explicit ArpCache(Context* context, const uint32_t localIp,
        const char* ifName, const char* routeFile = "/proc/net/route");
    ~ArpCache()
    {
        sys->close(fd);
        fd = -1;
        sys->close(fdArp);
        fdArp = -1;
    }
    bool arpLookup(const uint32_t destIp, EthernetHeader* ethHdr);

    // The maximum length of a NIC string name as defined in linux header files.
    static const int MAX_IFACE_LEN = IFNAMSIZ;

    // The MAC address length in bytes.
    static const int MAC_ADDR_LEN = 6;

    // Number of allowed retries to read Kernel's ARP Cache when the Kernel
    // Cache is busy and not available to be accessed by our code.
    static const int ARP_RETRIES = 10;

    // Number of micro seconds to wait before retrying to read Kernel's ARP
    // cache when the Kernel cache is busy.
    static const int ARP_WAIT = 200;

    /**
     * This class keeps a copy of a group of select entries of linux route table
     * located at routeFile (common address for routeFile is /proc/net/route).
     * In layer 3 networking, the ARP cache only contains the MAC address of the
     * machines that are on the same subnet as the source machine and gateways.
     * gateways are essentially the routers that forward the packets from 
     * the source machine destined to destination IPs that are located outside
     * of the subnet of source machine.
     * The purpose of route table in Kernel and also RouteTable class below is
     * to provide a way to resolve the gateway IP for any arbitrary
     * destination  address. Then using the ARP table and the gateway IP we can
     * resolve the next hop MAC address in the network for that destination IP.
     * The entries in Kernel's route table looks like this (in human readable
     * form as it appears as the output of "route -n" command):
     *
     *------------------------------------------------------------------------
     * Destination     Gateway      Genmask         Flags Metric Ref  Use Iface
     * 192.168.100.0   0.0.0.0      255.255.255.0   U     0      0      0 eth2
     *
     */
    class RouteTable {
      public:
        friend class ArpCache;
        explicit RouteTable(const char* ifName, const char* routeFile);
        uint32_t getGatewayIp(const uint32_t destIp);

        /**
         * This struct keeps a copy of a select group of parameters of route table
         * entries that we must have to resolve gateway IP for any arbitrary
         * distination IP.
         */
        struct RouteEntry {

            // The interface on which packets must be transmitted. This would be
            // same as the interface on which our driver is receiving and
            // sending packets.
            char ifName[MAX_IFACE_LEN];

            // The range of destination IPs that the source machine would only
            // be albe to communicate with them through the Gateway machine.
            // This value is in network byte order.
            uint32_t destIpRange;

            // Gateway IP address is the IP address of a machine on a network
            // through which the source machine would be able to communicate
            // with the machines with IP address in destIpRange. This value is
            // in network byte order.
            uint32_t gatewayIp;

            // netMask a long with destIpRange detemines the subnet network of
            // IP addresses that must use gatewayIp as their Gateway for that
            // network. This value is in network byte order.
            uint32_t netMask;
        };

      PRIVATE:

        // A vector containing the routing table entries.
        std::vector<RouteEntry> routeVector;

        DISALLOW_COPY_AND_ASSIGN(RouteTable);
    };

  PRIVATE:
    bool lookupKernelArpCache(const uint32_t destIp, EthernetHeader* ethHdr);
    void updateKernelArpCache(const uint8_t* ethPkt);
    void sendUdpPkt(struct sockaddr* destAddress);

    /**
     * Defines the object that will be stored in local IP-MAC cache. Each ip
     * address in the local cache will be hash-mapped to an instance of this
     * structure which contains the MAC address along with some other
     * information.
     */
    struct ArpEntry {

        // Default constructor.
        ArpEntry()
            : macAddress()
            , address()
            , valid(false)
        {}

        // The MAC adddress that we want to resolve for an IP address. The
        // ArpCache object keeps a copy of this MAC address for future queries
        // to resolve the MAC address.
        uint8_t macAddress[MAC_ADDR_LEN];

        // A socket address structure that contains the IP address of an IP-MAC
        // pair in ArpCache.
        struct sockaddr address;

        // This determines if the current value for MAC address field in this
        // structure is a valid resolution for the IP address in IpMacMap table.
        // The MAC address only is valid if it's been resolved through a
        // successful lookup on Kernel's ARP Cache.
        bool valid;
    };

    // Defines hash map (key-value table) from 32bit ip addresses(key) to Mac
    // addresses(value). The local IP-MAC cache (local ARP cache) will be an
    // instance of this IPMacMap. 32bit ip addresses are in network byte order.
    typedef std::unordered_map<uint32_t, ArpEntry> IpMacMap;

    // The local ARP cache that contains IP-MAC (IP-ArpEntry) resolution.
    IpMacMap ipMacMap;

    // The socket file descriptor for this ArpCache. This is used for sending
    // UDP packets to the IP address for which we want to resolve the MAC
    // address.
    int fd;

    // Socket file descriptor for performing ioctl on Kernel's ARP cache.
    int fdArp;

    // Keeps a local route table for fast gateway resolution.
    RouteTable routeTable;

    // RAMCloud shared information.
    Context* context;

    // Name of our local network interface correponding to the local IP. This is
    // the interface on which the driver (that owns ArpCache object) will use to
    // transmit and receive packets.
    char ifName[MAX_IFACE_LEN];

    // A socket address of type sockaddr_in that contains local IP of the
    // driver.
    struct sockaddr localAddress;
    static Syscall* sys;

    DISALLOW_COPY_AND_ASSIGN(ArpCache);
};
} //namespace RAMCloud
#endif //RAMCLOUD_ARPCACHE_H
