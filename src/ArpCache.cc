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


#include <net/if_arp.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <fstream>
#include "ArpCache.h"
#include "EthernetUtil.h"
#include "Common.h"
#include "ShortMacros.h"


namespace RAMCloud {

/**
 * Default object used to make system calls.
 */
static Syscall defaultSyscall;

/**
 * Used by this class to make all system calls.  In normal production
 * use it points to defaultSyscall; for testing it points to a mock
 * object.
 */
Syscall* ArpCache::sys = &defaultSyscall;


using namespace EthernetUtil; //NOLINT

/**
 * Constructor for ArpCache object.
 *
 * \param context
 *      Overall and shared information about RAMCloud client or server.
 * \param localIp
 *      The 32 bit IP address in netwrork byte order of the source. This is the
 *      ip address used as source ip in the header of every outgoing packet 
 *      that is transmitted from the driver that owns this instance of ARP
 *      Cache. 
 * \param ifName
 *      The name of network interface that owns localIp address.
 * \param routeFile
 *      The full name (including path) for Kernel's route table file. This
 *      file in most of linux distros is "/proc/net/route"
 */
ArpCache::ArpCache(Context* context, const uint32_t localIp,
        const char* ifName, const char* routeFile)
    : ipMacMap()
    , fd(-1)
    , fdArp(-1)
    , routeTable(ifName, routeFile)
    , context(context)
    , ifName()
    , localAddress()
{
    snprintf(this->ifName, MAX_IFACE_LEN, "%s", ifName);
    struct sockaddr_in *local = reinterpret_cast<sockaddr_in*>(&localAddress);
    local->sin_family = AF_INET;
    local->sin_addr.s_addr = localIp;

    // Let the kernel choose a port when we create the socket
    local->sin_port = HTONS(0);
    fd = sys->socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        throw Exception(HERE, "ArpCache could not open a socket for"
            " resolving mac addresses!", errno);
    }

    int r = sys->bind(fd, &localAddress, sizeof(localAddress));
    if (r < 0) {
        string msg = format("ArpCache could not bind the socket to %s",
            inet_ntoa(local->sin_addr));
        throw Exception(HERE, msg.c_str(), errno);
    }

    if ((fdArp = sys->socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        throw Exception(HERE, "Can't open socket for performing "
            "IO control", errno);
    }
}

/**
 * This function is the lookup interface of the ArpCache that is exposed 
 * to the users (driver code). 
 *  
 * \param destIp 
 *      32 bit destination ip (in network byte order) for which we want to
 *      resolve the MAC address.
 * \param ethHdr
 *      Pointer to the Ethernet header of Ehternet frame that is to be sent to
 *      the destIp. After this function successfully returns the destination
 *      address (destAddr field in the header) will be filled with the 
 *      appropriate MAC address for the destIp.
 *  \return
 *      True means that we have successfully resolved the MAC address and copied
 *      it over to destAddr field of ethHdr param. False, means that the
 *      function couldnot resolve MAC address. The failure of this method is
 *      assumed to be handles by higher level transport code. 
 */
bool
ArpCache::arpLookup(const uint32_t destIp, EthernetHeader* ethHdr)
{

    // It first tries to resolve the MAC address from local cache, if failed,
    // looks it up from kernel ARP cache, and if that fails too, triggers the
    // ARP module in the kernel to resolve that MAC address through the ARP
    // protocol and then resolves the MAC address from kernel cache. The last
    // will get retried for ARP_RETRIES times in ARP_WAIT micro second intervals
    // until it succeeds. If it doesn't succeed the function returns false.

    IpMacMap::iterator mapEntry = ipMacMap.find(destIp);

    // Lookup MAC in local cache.
    if (mapEntry != ipMacMap.end() && mapEntry->second.valid) {
        memcpy(ethHdr->destAddress, mapEntry->second.macAddress,
               sizeof(ethHdr->destAddress));
#if TESTING
        sockaddr_in remote;
        remote.sin_addr.s_addr = destIp;
        TEST_LOG("Resolved MAC address for host %s through local cache!",
            inet_ntoa(remote.sin_addr));
#endif
        return true;
    } else {

        // Resolve the gateway address for destination destIp
        uint32_t gatewayIp = routeTable.getGatewayIp(destIp);
        sockaddr_in remote;
        remote.sin_addr.s_addr = destIp;

        if (lookupKernelArpCache(gatewayIp, ethHdr)) {
            // Lookup MAC in Kernel ARP cache for the gateway. If successful,
            // update the local cache too.
            ArpEntry& arpEntry = ipMacMap[destIp];
            arpEntry.valid = true;
            memcpy(arpEntry.macAddress, ethHdr->destAddress,
                sizeof(arpEntry.macAddress));

            LOG(NOTICE, "Resolved MAC address through kernel calls for host at"
                " %s!", inet_ntoa(remote.sin_addr));
            return true;
        }

        ArpEntry& arpEntry = ipMacMap[destIp];
        struct sockaddr_in* destAddr =
            reinterpret_cast<sockaddr_in*>(&arpEntry.address);

        destAddr->sin_addr.s_addr = destIp;
        destAddr->sin_family = AF_INET;
        destAddr->sin_port = HTONS(static_cast<uint16_t>(generateRandom()));

        // Send a UDP packet to the destAddr which causes the kernel ARP
        // module to get triggered which updates kernel's ARP cache.
        sendUdpPkt(&arpEntry.address);
        if (!lookupKernelArpCache(gatewayIp, ethHdr)) {
            LOG(WARNING, "No success in resolving MAC address for host at %s!",
                inet_ntoa(remote.sin_addr));

            return false;
        } else {
            // Update local cache and return true.
            memcpy(arpEntry.macAddress, ethHdr->destAddress,
                sizeof(arpEntry.macAddress));
            arpEntry.valid = true;
            LOG(NOTICE, "Resolved MAC address through kernel calls and ARP"
                " packets for host at %s!", inet_ntoa(remote.sin_addr));
            return true;
        }
    }
}

/**
 * This method uses IO control command to lookup MAC address for a destination
 * IP address using Kernel's ARP cache. If the IO control fails, then the
 * function keeps trying for ARP_RETRIES times in ARP_WAIT micro sec intervals.
 *
 * \param destIp 
 *      32 bit destination ip ( in network byte order) for which we want to
 *      resolve the MAC address.
 * \param ethHdr
 *      Pointer to the Ethernet header of Ehternet frame that is to be sent to
 *      the destIp. After this function successfully returns the destination
 *      address (destAddr field in the header) will be filled with the 
 *      appropriate MAC address for the destIp.
 * \return
 *      True means that we have successfully resolved the MAC address and copied
 *      it over to destAddr field of ethHdr param. False, means that the
 *      function could not resolve MAC address as a result of one of these two 
 *      reasons:
 *      1) there is no entry match for destIp in Kernel's ARP cache. 
 *      2) There is an entry but it's either in busy state (meaning that it's
 *      being used by kernel) or it's not complete (meaning that the entry is
 *      not yes fully updated and ARP response packet has not yet been received)
 */
bool
ArpCache::lookupKernelArpCache(const uint32_t destIp, EthernetHeader* ethHdr)
{
    struct arpreq arpReq;
    memset(&arpReq, 0, sizeof(arpReq));

    struct sockaddr_in *sin =
        reinterpret_cast<sockaddr_in*>(&arpReq.arp_pa);

    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = destIp;
    snprintf(arpReq.arp_dev, sizeof(arpReq.arp_dev), "%s", this->ifName);

    int atfFlagCompleted = 0x02;

    for (int r = 0; r < ARP_RETRIES; r++) {

        if (sys->ioctl(fdArp, SIOCGARP, &arpReq) == -1) {
            LOG(NOTICE, "Can't perform ioctl on kernel's ARP Cache for"
                " host at %s!", inet_ntoa(sin->sin_addr));
            return false;
        }

        // If the ioctl, we wait for some time and try again.
        if (arpReq.arp_flags & atfFlagCompleted) {
            uint8_t* mac =
                reinterpret_cast<uint8_t*>(&arpReq.arp_ha.sa_data[0]);
            memcpy(ethHdr->destAddress, mac, sizeof(ethHdr->destAddress));
            return true;
        } else {
            LOG(NOTICE, "Kernel ARP cache entry for host at %s is in use!"
                " Sleeping for %d us then retry for %dth time",
                inet_ntoa(sin->sin_addr), ARP_WAIT, r+1);
            usleep(ARP_WAIT);
        }
    }
    return false;
}

/**
 * This method sends a dummy UDP packet to destAddress. The content of the
 * packet that is sent by this method is a constant string.
 *
 * \param destAddress
 *      Poniter to the sockaddr object that contains the destinations IP
 *      address.
 */
void
ArpCache::sendUdpPkt(struct sockaddr* destAddress)
{
    string udpPkt = "dummy msg!";

    // send the udp request packet out on the socket
    int sentBytes =
        downCast<int>(sys->sendto(fd, udpPkt.c_str(), udpPkt.length(),
            0, destAddress, sizeof(struct sockaddr)));

    if (sentBytes != downCast<int>(udpPkt.length())) {
        LOG(WARNING, "ARP UDP packet sent %d bytes. Pakcet lenght was %d",
            sentBytes, downCast<int>(udpPkt.length()));
    }
}

/**
 * Constructor for RouteTable class. This basically iterates over the Kernel's
 * route table and fills out the internal route table structure of this class
 * based on the information in Kernel's route file.
 * The Kernel's route file in linux is formatted as below:
 * ----------------------------------------------------------------------------
 * Iface  Destination  Gateway  Flags RefCnt Use Metric  Mask    MTU Window IRTT
 *
 *  eth2   0064A8C0    00000000  0001   0     0     0  00FFFFFF   0    0     0 
 * ----------------------------------------------------------------------------
 *  All the IP values in this route file are recorded as 32bit values in network
 *  byte order as in the above example.
 *
 * \param ifName
 *      The interface name for which we want to keep the route inforamtion
 *      provided in the Kernel's route table.
 * \param routeFile
 *      Name (including the full path) to the file that contains Kernel's route
 *      table (as specified in table above). In most Linux ditstros this file is
 *      located at /proc/net/route.
 */
ArpCache::RouteTable::RouteTable(const char* ifName, const char* routeFile)
    :routeVector()
{
    std::ifstream routeStream(routeFile);
    string line;
    getline(routeStream, line);
    std::vector<string> routeVec;
    RouteEntry routeEntry;

    // Iterate over all the lines in the routeFile and parse out the paramaters
    // the parameters in the file. writes the parsed parameters in routeVec
    // vector.
    while (getline(routeStream, line)) {
        routeVec.clear();
        while (line.size()) {
            for (size_t pos = 0; pos < line.size(); ++pos) {
                if (isspace(line[pos])) {
                    if (pos == 0) {
                        line.erase(0, 1);
                    } else {
                        routeVec.push_back(line.substr(0, pos));
                        line.erase(0, pos);
                    }
                    break;
                }

                if (pos == line.size() - 1) {
                    routeVec.push_back(line);
                    line.erase();
                }
            }
        }

        // If the interface name for the line that we just parsed out from
        // routeFile is same as the ifName, then we will keep that route entry
        // in our local route table.
        if (strcmp(routeVec[0].c_str(), ifName) == 0) {
            snprintf(routeEntry.ifName, sizeof(routeEntry.ifName),
                "%s", ifName);
            routeEntry.destIpRange =
                downCast<uint32_t>(strtoul(routeVec[1].c_str(), NULL, 16));
            routeEntry.gatewayIp =
                downCast<uint32_t>(strtoul(routeVec[2].c_str(), NULL, 16));
            routeEntry.netMask =
                downCast<uint32_t>(strtoul(routeVec[7].c_str(), NULL, 16));
            routeVector.push_back(routeEntry);
        }
    }
}

/**
 * This method takes in a distanation IP and looks up the gateway IP for that
 * destination. This method only searched the local cache of route table for the
 * interface name that was specified as the input argument of constructor for
 * RouteTable class. This method uses longest prefix matching as the mathcing
 * rule for finding the gateway IP.
 *
 * \param destIp
 *      32 bit IP address (in network byte order) of the destination that we
 *      want to gateway IP for it.
 * \return
 *      32 bit IP address (in network byte order) of the gateway. If function
 *      finds a nonzero gateway based on the longest prefix matching rule, then
 *      it returns it. Otherwise, it will return the input argument destIp as
 *      the gateway address.
 */
uint32_t
ArpCache::RouteTable::getGatewayIp(const uint32_t destIp)
{
    uint32_t mask = 0;
    uint32_t gateway = 0;
    for (size_t i = 0; i < routeVector.size(); ++i) {
        RouteEntry& entry = routeVector[i];
        if ((entry.destIpRange & entry.netMask) == (destIp & entry.netMask) &&
                entry.netMask >= mask) {
            mask = entry.netMask;
            gateway = entry.gatewayIp;
        }
    }
    return gateway ? gateway : destIp;
}

} //namespace RAMCloud
