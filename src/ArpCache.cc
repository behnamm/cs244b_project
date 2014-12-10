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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/file.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#include <arpa/inet.h>
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
 *
 *
 */
ArpCache::ArpCache(Context* context, Driver* driver, uint32_t localIp)
    : ipMacMap()
    , fd(-1)
    , context(context) 
    , driver(driver)
    , localAddress()
{
    struct sockaddr_in *local = reinterpret_cast<sockaddr_in*>(&localAddress);
    local->sin_family = AF_INET;
    local->sin_addr.s_addr = localIp;

    // Let the kernel choose a port when we creat the socket
    local->sin_port = HTONS(0);
    fd = sys->socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        DIE("ArpCache could not open a socket for resolving mac addresses!");
    }
  
    int r = sys->bind(fd, &localAddress, sizeof(localAddress));
    if (r < 0) {
        DIE("ArpCache could not bind the socket to provided local addres");
    }
    Dispatch::Lock lock(context->dispatch); 
}

bool
ArpCache::arpLookup(uint8_t* ethPkt,
                    const char* ifName)
{
    EthernetHeader* ethHdr =
        reinterpret_cast<EthernetHeader*>(ethPkt);
    IpHeader* ipHdr = reinterpret_cast<IpHeader*>(
                      reinterpret_cast<char*>(ethPkt) + sizeof(EthernetHeader));
    
    uint32_t destIp = ipHdr->ipDestAddress;
    IpMacMap::iterator mapEntry = ipMacMap.find(destIp);
    if (mapEntry != ipMacMap.end() && mapEntry->second.valid) {
        memcpy(ethHdr->destAddress, mapEntry->second.macAddress,
               sizeof(ethHdr->destAddress)); 
        return true;
    } else if (lookupKernelArpCache(destIp, ifName, ethHdr)) {
        ArpEntry& arpEntry = ipMacMap[destIp];
        arpEntry.valid = true;
        strcpy(arpEntry.ifName, ifName);
        memcpy(arpEntry.macAddress, ethHdr->destAddress,
            sizeof(arpEntry.macAddress));
        return true;
    } 

    ArpEntry& arpEntry = ipMacMap[destIp];
    strcpy(arpEntry.ifName, ifName);
    struct sockaddr_in* destAddr =
        reinterpret_cast<sockaddr_in*>(&arpEntry.address);

    destAddr->sin_addr.s_addr = destIp;
    destAddr->sin_family = AF_INET;
    destAddr->sin_port = HTONS(static_cast<uint16_t>(generateRandom()));

    // Send a UDP packet to the destAddr which causes the kernel ARP
    // module to get triggered which updates kernel's ARP cache.
    sendUdpPkt(&arpEntry.address);
    if (!lookupKernelArpCache(destIp, ifName, ethHdr)) {
        return false;
    } else {
        memcpy(arpEntry.macAddress, ethHdr->destAddress,
            sizeof(arpEntry.macAddress));
        arpEntry.valid = true;
        return true;
    }
}

bool
ArpCache::lookupKernelArpCache(const uint32_t destIp, const char* ifName,
    EthernetHeader* ethHdr)
{
    struct arpreq arpReq;
    memset(&arpReq, 0, sizeof(arpReq));

    struct sockaddr_in *sin =
        reinterpret_cast<sockaddr_in*>(&arpReq.arp_pa);
           
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = destIp;
    strcpy(arpReq.arp_dev, ifName);

    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        DIE("Can't open socket for performing IO control");
    }
    int atfFlagCompleted = 0x02;
        
    for (int r = 0; r < ARP_RETRIES; r++) {

        if (ioctl(fd, SIOCGARP, &arpReq) == -1) {
            close(fd);
            LOG(NOTICE, "Can't perform ioctl on kernel's ARP Cache!");
            return false;
        }
        
        if (arpReq.arp_flags & atfFlagCompleted) {
            uint8_t* mac = reinterpret_cast<uint8_t*>(&arpReq.arp_ha.sa_data[0]); 
            memcpy(ethHdr->destAddress, mac, sizeof(ethHdr->destAddress));
            close(fd);
            return true;
        } else {
            LOG(NOTICE, "Kernel ARP cache entry is in use! Sleeping for"
                " %d us then retry for %dth time", ARP_WAIT, r+1);
            usleep(ARP_WAIT);
        }
    }
    close(fd);
    return false;
}

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


} //namespace RAMCloud
