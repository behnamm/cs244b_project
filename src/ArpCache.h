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

#include "Syscall.h"
#include "Dispatch.h"
#include "Tub.h"
#include "Driver.h"

namespace RAMCloud {

/**
 * ArpCache provides local table for IP-MAC translation. Layer 3 driver codes
 * will refer to this cache to resolve the MAC address of a remote node based on
 * the ip address of that node and the ethernet interface of the local node
 * through which the driver code will communicate with the remote node.
 */
class ArpCache {
  public:
    class ArpPing;
    explicit ArpCache(Context* context, Driver* driver);
    
    bool arpLookup(uint8_t* ethPkt, uint32_t packetLen,
                   const char* ifName);

    static const int MAX_IFACE_LEN = 16;
    static const int MAC_ADDR_LEN = 6;

    struct QueuedPacket {
        QueuedPacket()
            : next(NULL)
            , packetLen(0)
            , ethPkt()
        {}

        struct QueuedPacket* next; 
        uint32_t packetLen;
        uint8_t ethPkt[MAC_ADDR_LEN];  
    };

    class ArpPingSocketHandler : public Dispatch::File {
      public:
        ArpPingSocketHandler(int fd, ArpPing* arpPing);
        virtual void handleFileEvent(int events);
      PRIVATE:
        int fd;
        ArpPing* arpPing;
        DISALLOW_COPY_AND_ASSIGN(ArpPingSocketHandler);
    };

    class ArpPing {
      public:
        friend class ArpPingSocketHandler;
        explicit ArpPing(ArpCache* arpCache, uint32_t destIp);
        ~ArpPing();
        void sendPing();
        void handlePong();
      PRIVATE:
        ArpCache* arpCache;
        struct sockaddr address;
        int fd;
        int pingPktLen;
        Tub<ArpPingSocketHandler> arpPingIoHandler;
        
        uint16_t cksum(const uint8_t* pkt, int len);
        DISALLOW_COPY_AND_ASSIGN(ArpPing);
    };

    struct ArpEntry {
        ArpEntry()
            : head(NULL)
            , tail(NULL)
            , ifName()
            , macAddress()
            , arpPing(NULL)
        {}

        struct QueuedPacket* head; 
        struct QueuedPacket* tail;
        char ifName[MAX_IFACE_LEN];
        uint8_t macAddress[MAC_ADDR_LEN];
        ArpPing* arpPing;
    };


  PRIVATE:
    friend class ArpPing;
    typedef std::unordered_map<uint32_t, ArpEntry> IpMacMap;
    
    // The internal staructure that contains the IP-MAC pairs. 
    IpMacMap ipMacMap;
    uint16_t pingSeqNum;
    uint16_t pingIdent;
    static Syscall* sys;
    const string lookupKernelArpCache(const uint32_t destIp,
        const char* ifName);
        
    void updateKernelArpCache(const uint8_t* ethPkt);

    
    Context* context;
    Driver* driver;
    DISALLOW_COPY_AND_ASSIGN(ArpCache);
};
} //namespace RAMCloud
#endif //RAMCLOUD_ARPCACHE_H
