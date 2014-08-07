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

ArpCache::ArpCache(Context* context, Driver* driver)
    : ipMacMap()
    , pingSeqNum(0)
    , pingIdent(static_cast<uint16_t>(generateRandom()))
    , context(context) 
    , driver(driver)
{}

bool
ArpCache::arpLookup(uint8_t* ethPkt, uint32_t packetLen,
                    const char* ifName)
{
    EthernetHeader* ethHdr =
        reinterpret_cast<EthernetHeader*>(ethPkt);
    IpHeader* ipHdr = reinterpret_cast<IpHeader*>(
                      reinterpret_cast<char*>(ethPkt) + sizeof(EthernetHeader));
    
    uint32_t destIp = ipHdr->ipDestAddress;
    IpMacMap::iterator mapEntry = ipMacMap.find(destIp);
    if (mapEntry != ipMacMap.end() && !mapEntry->second.head) {
        memcpy(ethHdr->destAddress, mapEntry->second.macAddress,
               sizeof(ethHdr->destAddress)); 
        return true;
    } else if (mapEntry == ipMacMap.end()) {
        string macStr = lookupKernelArpCache(destIp, ifName);
        if (!macStr.empty()) {
            const uint8_t* mac = reinterpret_cast<const uint8_t*>(macStr.c_str());
            memcpy(ethHdr->destAddress, mac, sizeof(ethHdr->destAddress));
            ArpEntry arpEntry;
            strcpy(arpEntry.ifName, ifName);
            memcpy(arpEntry.macAddress, mac, sizeof(arpEntry.macAddress));
            ipMacMap[destIp] = arpEntry;
            return true;
        }
    } 

    // queue the packet and ping the other end to trigger kernel 
    // ARP request.
    struct QueuedPacket* pkt = new QueuedPacket; 
    pkt->packetLen = packetLen;
    memcpy(pkt->ethPkt, ethPkt, packetLen);

    ArpEntry& arpEntry = ipMacMap[destIp];
    
    if (!arpEntry.head) {
        assert(arpEntry.tail == NULL);
        pkt->next = NULL;
        arpEntry.head = pkt;
        arpEntry.tail = pkt;
    } else {
        pkt->next = NULL;
        arpEntry.tail->next = pkt;
        arpEntry.tail = pkt;
    }

    if (!arpEntry.arpPing) {
        strcpy(arpEntry.ifName, ifName);
        arpEntry.arpPing = new ArpPing(this, destIp);   
        arpEntry.arpPing->sendPing();
    }
    return false;
}

const string
ArpCache::lookupKernelArpCache(const uint32_t destIp, const char* ifName)
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
    
    if (ioctl(fd, SIOCGIFADDR, &arpReq) == -1) {
        close(fd);
        return string();
    }
    close(fd);
    
    int atfFlagCompleted = 2;
    if (arpReq.arp_flags & atfFlagCompleted) {
        char mac[sizeof(MAC_ADDR_LEN) + 1]; 
        memcpy(mac, arpReq.arp_ha.sa_data, sizeof(mac));
        mac[sizeof(mac)] = '\0';
        return string(mac);
    } else {
        return string();
    }
}

ArpCache::ArpPingSocketHandler::ArpPingSocketHandler(int fd,
        ArpPing* arpPing)
    : Dispatch::File(arpPing->arpCache->context->dispatch, fd, 
        Dispatch::FileEvent::READABLE)
    , fd(fd) 
    , arpPing(arpPing)
{
    // Empty constructor
}

void
ArpCache::ArpPingSocketHandler::handleFileEvent(int events)
{
    uint8_t buf[arpPing->pingPktLen];
    socklen_t addrLen = sizeof(arpPing->address);
    size_t bytesRecv =
        sys->recvfrom(fd, buf, arpPing->pingPktLen, MSG_DONTWAIT,
            &arpPing->address, &addrLen);
    if (bytesRecv > 0) {
        if (downCast<int>(bytesRecv) != arpPing->pingPktLen) {
            LOG(WARNING, "ping reply: expected to receive %d bytes packet but"
                " actually received %zd bytes.",
                arpPing->pingPktLen, bytesRecv);
        }

        // probably check the seq no. to make sure this is the 
        // right ping respose.

        arpPing->handlePong();
    }
}

ArpCache::ArpPing::ArpPing(ArpCache* arpCache, uint32_t destIp)
    : arpCache(arpCache)
    , address()
    , fd(-1)
    , pingPktLen(0)
    , arpPingIoHandler()
{
    struct sockaddr_in *dest = reinterpret_cast<sockaddr_in*>(&address);
    dest->sin_family = AF_INET;
    dest->sin_addr.s_addr = destIp;
    struct protoent* proto = getprotobyname("icmp");
    if (proto == NULL) {
        DIE("icmp protocol is not know on this machine!");
    }

    fd = sys->socket(AF_INET, SOCK_RAW, proto->p_proto);
    if (fd < 0) {
        DIE("ArpPing could not open a socket to resolve mac address!");
    }
   
    Dispatch::Lock lock(arpCache->context->dispatch); 
    arpPingIoHandler.construct(fd, this);

}

void
ArpCache::ArpPing::sendPing()
{
    struct icmp icmpPkt;
    icmpPkt.icmp_type = ICMP_ECHO;
    icmpPkt.icmp_code = 0;
    icmpPkt.icmp_cksum = 0;
    icmpPkt.icmp_seq = arpCache->pingSeqNum++;
    icmpPkt.icmp_id = arpCache->pingIdent;
    pingPktLen = sizeof(icmpPkt.icmp_type) + sizeof(icmpPkt.icmp_code) +
        sizeof(icmpPkt.icmp_cksum) + sizeof(icmpPkt.icmp_seq) +
        sizeof(icmpPkt.icmp_id);
    
    uint8_t *pkt = reinterpret_cast<uint8_t*>(&icmpPkt);
    icmpPkt.icmp_cksum = cksum(pkt, pingPktLen);
    
    // send the ping request packet out on the socket
    int sentBytes = 
        downCast<int>(sys->sendto(fd, pkt, pingPktLen, 0, &address,
        sizeof(struct sockaddr)));

    if (sentBytes != pingPktLen) {
        LOG(WARNING, "ping sent %d bytes. Pakcet lenght was %d",
            sentBytes, pingPktLen);
    }
}

void
ArpCache::ArpPing::handlePong()
{
    sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(&address);
    uint32_t destIp = addr->sin_addr.s_addr;    
    ArpEntry* arpEntry = &(arpCache->ipMacMap[destIp]);
    string macStr = arpCache->lookupKernelArpCache(destIp, arpEntry->ifName);
    if (macStr.empty()) {
        DIE("The kernel arp cache is still empty after we received the the pong"
            " response. This is weird! maybe the corresponding kernel arp entry"
            " is  timed out.");
    }
    
    const uint8_t* mac = reinterpret_cast<const uint8_t*>(macStr.c_str());
    memcpy(arpEntry->macAddress, mac, sizeof(arpEntry->macAddress)); 

    // Go through the linked list of queued packets and transmit them.
    QueuedPacket* pkt = NULL; 
    while ((pkt = arpEntry->head)) {
        arpEntry->head = arpEntry->head->next;
        arpCache->driver->sendEthPacket(pkt->ethPkt, pkt->packetLen);
        free(pkt);
    }
    arpEntry->tail = NULL;
    
    // NOTE: we also need to free the arpEntry.arpPing here however it's a bit
    // tricky because we have to call it's destrcutor from withing itself
}

uint16_t
ArpCache::ArpPing::cksum(const uint8_t* pkt, int len)
{
    uint32_t sum;
    for (sum = 0;len >= 2; pkt += 2, len -= 2) {
        sum += pkt[0] << 8 | pkt[1];
    }
    if (len > 0)
        sum += pkt[0] << 8;
    while (sum > 0xffff) {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    uint16_t ret = HTONS(downCast<uint16_t>(~sum));
    return ret ? ret : downCast<uint16_t>(0xffff);
}

} //namespace RAMCloud
