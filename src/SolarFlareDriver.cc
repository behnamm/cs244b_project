/** Copyright (c) 2014 Stanford University
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

#include <net/if.h>
#include "SolarFlareDriver.h"
#include "FastTransport.h"
#include "Memory.h"
#include "Buffer.h"
#include "IpAddress.h"
#include "MacAddress.h"
#include "Syscall.h"

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
Syscall* SolarFlareDriver::sys = &defaultSyscall;

using namespace EthernetUtil; //NOLINT

/**
 * Constructs a SolarFlareDriver 
 * \param context
 *      Overall information about the RAMCloud server or client.
 * \param localServiceLocator 
 *      Specifies the mac address, IP address, and port that will be used to 
 *      to send and receive packets.
 */
SolarFlareDriver::SolarFlareDriver(Context* context,
                                   const ServiceLocator* localServiceLocator)
    : context(context)
    , arpCache()
    , localStringLocator()
    , localAddress()
    , incomingPacketHandler()
    , driverHandle()
    , protectionDomain()
    , logMemoryReg()
    , logBase(0)
    , logBytes(0)
    , virtualInterface()
    , rxBufferPool()
    , txBufferPool()
    , rxPrefixLen()
    , buffsNotReleased(0)
    , rxPktsReadyToPush(0)
    , numRxPktsToPost(0)
    , fd(-1)
    , sockAddr()
    , poller()
{
    if (localServiceLocator == NULL) {
        string localIpStr =  getLocalIp("eth0");
        sockaddr_in *sockInAddr = reinterpret_cast<sockaddr_in*>(&sockAddr);
        sockInAddr->sin_family = AF_INET;
        inet_aton(localIpStr.c_str(), &sockInAddr->sin_addr);

        // Let the kernel choose a port when we create the socket
        sockInAddr->sin_port = HTONS(0);
        fd = sys->socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            throw Exception(HERE, "Could not create socket for"
                " SolarFlareDrvier", errno);
        }
        
        int r = sys->bind(fd, &sockAddr, sizeof(sockAddr));
        if (r < 0) {
            sys->close(fd);
            string msg =
                format("SolarFlareDriver could not bind the socket to %s",
                inet_ntoa(sockInAddr->sin_addr));
            LOG(WARNING,"%s", msg.c_str());
            throw Exception(HERE, msg.c_str(), errno);
        }

        int optval = 1;
        r = 
            sys->setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval,
            sizeof(optval));
        if (r != 0) {
            sys->close(fd);
            string msg = 
                format("SolarFlareDriver couldn't set SO_REUSEADDR on "
                "listen socket: %s", strerror(errno));
            LOG(WARNING, "%s", msg.c_str());
            throw TransportException(HERE,
                    "SolarFlareDriver couldn't set SO_REUSEADDR on listen socket",
                    errno);
        }

        socklen_t sockAddrLen;
        sys->getsockname(fd, &sockAddr, &sockAddrLen);

        // If localServiceLocator is NULL, we have to make a locatorString for
        // this driver. We use the actual MAC and IP address of this machine
        // along with a randomly generated number for port.
        std::stringstream locatorStream;
        locatorStream << "fast+sf:mac=" << getLocalMac("eth0").c_str() << ",";
        locatorStream << "host=" << localIpStr.c_str() << ",";
        locatorStream << "port=" << NTOHS(sockInAddr->sin_port);

        ServiceLocator sl(locatorStream.str().c_str());
        localStringLocator = sl.getOriginalString();
        LOG(NOTICE, "No SolarFlare locator provided! "
            "Created the locator string: %s"
            , localStringLocator.c_str());
        localAddress.construct(sl);
    } else if (!localServiceLocator->getOption<const char*>("mac", NULL)) {
        std::stringstream macStream;
        macStream << ",mac=" << getLocalMac("eth0").c_str();
        localStringLocator = localServiceLocator->getOriginalString();
        ServiceLocator sl(localStringLocator + macStream.str());
        localAddress.construct(sl);
    } else {
        localStringLocator = localServiceLocator->getOriginalString();
        localAddress.construct(*localServiceLocator);
    }

    // Adapter initializations. Fills driverHandle with driver resources
    // that is needed to talk to the NIC.
    int rc = ef_driver_open(&driverHandle);
    if (rc < 0) {
        DIE("Failed to open driver for SolarFlare NIC!");
    }

    // Allocates protection domain which specifies how memory must be protected
    // for the VI of this driver.
    rc =  ef_pd_alloc(&protectionDomain, driverHandle, if_nametoindex("eth0"),
                       EF_PD_VF);
    if (rc < 0) {
        DIE("Failed to allocate a protection domain for SolarFlareDriver!");
    }

    // Allocates an RX and TX ring, an event queue, timers and interrupt on the
    // adapter card and fills out the structures needed to access them in
    // the software.
    rc = ef_vi_alloc_from_pd(&virtualInterface, driverHandle, &protectionDomain,
                             driverHandle, -1, -1, -1, NULL, -1,
                             static_cast<enum ef_vi_flags>(0));

    if (rc < 0) {
        DIE("Failed to allocate VI for SolarFlareDriver!");
    }

    // Setting filters on the NIC. SolarFlare NIC by default sends all the
    // packets to the kernel except for the ones that match filters below.
    // Those are sent to be handled by this driver.
    ef_filter_spec filterSpec;
    ef_filter_spec_init(&filterSpec, EF_FILTER_FLAG_NONE);
    const sockaddr_in *addr = reinterpret_cast<const sockaddr_in*>
                                   (&localAddress->ipAddress->address);
    uint32_t localIp = addr->sin_addr.s_addr;
    uint32_t localPort = addr->sin_port;

    rc = ef_filter_spec_set_ip4_local(&filterSpec, IPPROTO_UDP, localIp,
                                 localPort);
    if (rc < 0) {
        DIE("Failed to set filter specifications for SolarFlareDriver!");
    }
    rc = ef_vi_filter_add(&virtualInterface, driverHandle, &filterSpec, NULL);
    if (rc < 0) {
        DIE("Failed to add the specified filter to the SolarFlare NIC!");
    }

    rxPrefixLen = ef_vi_receive_prefix_len(&virtualInterface);

    // 32 large RPC size worth of packets to be allocated for receiving packets.
    // Might not be enough if 32 different clients try to read large RPCs from
    // a single server.
    int numRxBuffers = getMaxRpcLen() * 32 / ADAPTER_BUFFER_SIZE;  
    int rxBufferSize = ADAPTER_BUFFER_SIZE;
    rxBufferPool.construct(rxBufferSize, numRxBuffers, this);
    refillRxRing(RX_RING_CAP);
    
    int txBufferSize = ADAPTER_BUFFER_SIZE;
    int numTxBuffers = TX_RING_CAP;
    txBufferPool.construct(txBufferSize, numTxBuffers, this);
    arpCache.construct(context, localIp, "eth0");
}

/**
 * Constructor for RegisteredBuffs object. *
 * \param bufferSize
 *      Size of each packet buffer in the freeBufferList.
 * \param numBuffers
 *      Total number of packetBuffs to be registered to NIC in this class.
 * \param driver
 *      Pointer to the SolarFlareDriver that owns this instance of
 *      RegisteredBuffs class.
 */
SolarFlareDriver::RegisteredBuffs::RegisteredBuffs(int bufferSize,
    int numBuffers, SolarFlareDriver* driver)
    : memoryChunk()
    , registeredMemRegion()
    , bufferSize(bufferSize) 
    , numBuffers(numBuffers)
    , freeBufferList()
    , driver(driver)
{
    int totalBytes = bufferSize * numBuffers;
    // Allocates a chunk of memory that is aligned to the page size.
    memoryChunk = static_cast<char*>(Memory::xmemalign(HERE, 4096, totalBytes));
    if (!memoryChunk) {
        DIE("Failed to allocate for receive Buffers for SolarFlare Driver!");
    }

    // Register the memory chunk to NIC.
    int rc = 
        ef_memreg_alloc(&registeredMemRegion, driver->driverHandle,
        &driver->protectionDomain, driver->driverHandle,
        memoryChunk, totalBytes);
    if (rc < 0) {
        DIE("Failed to allocate a registered memory region in SolarFlare NIC"
        " for transmit packet buffers!");
    }
    
    // Divides the chunk into PacketBuffs and link them into a list.
    struct PacketBuff* head = NULL;
    for (int i = 0; i < numBuffers; i++) {
        struct PacketBuff* packetBuff =
            reinterpret_cast<PacketBuff*>(memoryChunk + i * bufferSize);

        packetBuff->id = i;
        packetBuff->dmaBufferAddress = ef_memreg_dma_addr(&registeredMemRegion,
                                        i * bufferSize);
        packetBuff->dmaBufferAddress += OFFSET_OF(struct PacketBuff,
                                                  dmaBuffer);
        packetBuff->next = head;
        head = packetBuff;
    }
    freeBufferList = head;
}

/**
 * A helper function to find the address of an specific PacketBuff within the
 * memory chunk of RegisteredBuffs class.
 *
 * \param packetId
 *      The packetId of the PacketBuff that we want to find its address. This
 *      parameter must be less than #RegisteredBuffs::numBuffers.
 * \return
 *      A pointer to the retrieved PacketBuff.
 */
SolarFlareDriver::PacketBuff*
SolarFlareDriver::RegisteredBuffs::getBufferById(int packetId)
{
    assert(packetId < numBuffers);
    return reinterpret_cast<struct PacketBuff*>( memoryChunk 
        + packetId * bufferSize);
}

/**
 * It will return a PacketBuff that's been released from the RX or TX ring to
 * the owning RegisteredBuffs object.
 * 
 * \param packetBuff
 *      Address of the PacketBuff that is to be returned to the free list. This
 *      functions makes necessary checks to verify that packetBuff belong to the
 *      this RegisteredBuffs instance.
 */
void
SolarFlareDriver::RegisteredBuffs::prependToList(PacketBuff* packetBuff)
{
    assert(reinterpret_cast<char*>(packetBuff) >= memoryChunk &&
        reinterpret_cast<char*>(packetBuff) < (memoryChunk +
        bufferSize * numBuffers));
    packetBuff->next = freeBufferList;
    freeBufferList = packetBuff;
}

/**
 * Given a packetId of a PacketBuff that's been just released from RX ring or
 * unbundled from TX ring, this function returns that PacketBuff to the
 * RegisteredBuffs class that owns it and prepares it to be reused in RX or TX
 * rings.
 *
 * \param packetId
 *      The packetId of the packetBuff to be returned to the free list of
 *      buffers.
 */
void
SolarFlareDriver::RegisteredBuffs::prependToListById(int packetId)
{
    struct PacketBuff* packetBuff = getBufferById(packetId);
    packetBuff->next = freeBufferList;
    freeBufferList = packetBuff;
}

/**
 * Returns a free and ready to use PacketBuff from the freeBufferList and
 * removes it from the list.
 *
 * \return
 *      A pointer to a free PacketBuff that is removed from the list. Null, if
 *      no PacketBuff left free on the list.
 */
SolarFlareDriver::PacketBuff*
SolarFlareDriver::RegisteredBuffs::popFreeBuffer()
{
    if (!freeBufferList)
        return NULL;
    PacketBuff* head = freeBufferList;
    freeBufferList = freeBufferList->next;
    return head;
}




/**
 * A helper method to push back the received packet buffer to the RX
 * descriptor ring. This should be called either in the constructor of the 
 * SolareFlareDriver or after the packet is polled off of the NIC and handled.
 *
 * \param numPktToPost
 *      The total number of packets to be posted to the RX ring in single call
 *      to this function. This value is usually equal to the number of packets
 *      that are popped off of the RX ring after every call to poll() function.
 *  
 * \return
 *      The actual number of packets that's been posted on the RX ring. This is
 *      usually equal to the numPktToPost unless there are not enough number of
 *      PacketBuffs ready to use.
 */
int
SolarFlareDriver::refillRxRing(int numPktToPost)
{

    // Pushing packets to the RX ring happens in two steps. First we must
    // initialize the packet to the VI and then we push it to the RX ring.
    for (int i = 0; i < numPktToPost; i++) {
        PacketBuff* pktBuf = rxBufferPool->popFreeBuffer();
        if (!pktBuf) {
            LOG(WARNING, "No packet buffer left free to push to RX ring of"
            " SolarFlare NIC.");
            return i;
        }

        // ef_vi_receive_init() initialized the packet to the VI but
        // doesn't actually push it. This function is fast so we call it for
        // every individual packet in the free list.
        ef_vi_receive_init(&virtualInterface,
                           pktBuf->dmaBufferAddress,
                           pktBuf->id);
        rxPktsReadyToPush++;

        // ef_vi_receive_push() does the actual job of pushing initialized
        // packets to RX ring and it is much slower than initializing function
        // so we call it for a batch of RX_REFILL_BATCH_SIZE buffers
        // that have been already initialized.
        if (rxPktsReadyToPush == RX_REFILL_BATCH_SIZE) {
            ef_vi_receive_push(&virtualInterface);
            rxPktsReadyToPush = 0;
        }
    }
    return numPktToPost;
}

/**
 * Destroys a SolareFlareDriver and frees all the resources.
 */
SolarFlareDriver::~SolarFlareDriver() {
    if (buffsNotReleased != 0) {
        LOG(WARNING, "%lu packets are not released",
            buffsNotReleased);
    }
    ef_vi_free(&virtualInterface, driverHandle);
    ef_pd_free(&protectionDomain, driverHandle);
    ef_driver_close(driverHandle);
    rxBufferPool.destroy();
    txBufferPool.destroy();
    if (fd < 0) {
        sys->close(fd);
    }
} 

// See docs in the ``Driver'' class.
void
SolarFlareDriver::connect(IncomingPacketHandler* incomingPacketHandler)
{
    this->incomingPacketHandler.reset(incomingPacketHandler);
    poller.construct(context, this);
}

// See docs in the ``Driver'' class.
void
SolarFlareDriver::disconnect()
{
    poller.destroy();
    this->incomingPacketHandler.reset();
}

// See docs in the ``Driver'' class.
uint32_t
SolarFlareDriver::getMaxPacketSize()
{
    return ETHERNET_MAX_DATA_LEN -
           downCast<uint32_t>(sizeof(IpHeader) + sizeof(UdpHeader));
}

// See docs in the ``Driver'' class.
void
SolarFlareDriver::release(char* payload)
{
    Dispatch::Lock _(context->dispatch);
    assert(buffsNotReleased > 0);
    buffsNotReleased--;
    PacketBuff* packetBuff =
       reinterpret_cast<PacketBuff*>(payload -
       OFFSET_OF(PacketBuff, dmaBuffer) -
       ETH_DATA_OFFSET -
       rxPrefixLen);

    rxBufferPool->prependToList(packetBuff);
}

// See docs in the ``Driver'' class.
void
SolarFlareDriver::sendPacket(const Driver::Address* recipient,
                             const void* header,
                             const uint32_t headerLen,
                             Buffer::Iterator *payload)
{

    uint32_t udpPayloadLen = downCast<uint32_t>(headerLen
                                + (payload ? payload->size() : 0));
    uint16_t udpLen = downCast<uint16_t>(udpPayloadLen + sizeof(UdpHeader));
    uint16_t ipLen = downCast<uint16_t>(udpLen + sizeof(IpHeader));
    assert(udpPayloadLen <= getMaxPacketSize());

    const SolarFlareAddress* recipientAddress =
        static_cast<const SolarFlareAddress*>(recipient);

    // Max number of iovec required. We need at least one for the Eth+IP+UDP
    // headers. We need one for the header if it happens to be in registered log
    // memory. And we need number of chunks iovecs if payload is in the
    // registered log memory region.
    uint32_t maxIovecs = 2 + (payload ? payload->getNumberChunks() : 0);
    ef_iovec iovec[maxIovecs];
    
    // The actual number of the iovecs that we will use.
    int numIovecs = 0;

    // We need one transmit buffer for the Eth+IP+UDP header and possibly the
    // whole message if the payload is not in the log memory.
    PacketBuff* txRegisteredBuf = txBufferPool->popFreeBuffer();
    while (!txRegisteredBuf) {

        // No buffer is available, we have to poll on the event queue
        // to get a transmit buffer that's finished transmission.
        LOG(NOTICE, "No free TX buffer available! Calling poll() to"
            " get free buffers");
        context->dispatch->poll();
    }
    
    // Fill Ethernet header except recipient's mac address
    EthernetHeader* ethHdr = new(txRegisteredBuf->dmaBuffer) EthernetHeader;
    memcpy(ethHdr->srcAddress, localAddress->macAddress->address,
           sizeof(ethHdr->srcAddress));
    ethHdr->etherType = HTONS(EthernetType::IP_V4);

    // Fill IP header
    IpHeader* ipHdr =
        new(reinterpret_cast<char*>(ethHdr) + sizeof(EthernetHeader))IpHeader;
    ipHdr->ipIhlVersion = (4u << 4u) | (sizeof(IpHeader) >> 2u);
    ipHdr->tos = 0;
    ipHdr->totalLength = HTONS(ipLen);
    ipHdr->id = 0;
    ipHdr->fragmentOffset = 0;
    ipHdr->ttl = 64;
    ipHdr->ipProtocol = static_cast<uint8_t>(IPPROTO_UDP);
    ipHdr->headerChecksum = 0;
    sockaddr_in* srcAddr =
        reinterpret_cast<sockaddr_in*>(&localAddress->ipAddress->address);
    ipHdr->ipSrcAddress = srcAddr->sin_addr.s_addr;
    const sockaddr_in* destAddr = reinterpret_cast<const sockaddr_in*>(
                                       &recipientAddress->ipAddress->address);
    ipHdr->ipDestAddress = destAddr->sin_addr.s_addr;

    // Fill UDP header
    UdpHeader* udpHdr =
        new(reinterpret_cast<char*>(ipHdr) + sizeof(IpHeader)) UdpHeader;
    udpHdr->srcPort = srcAddr->sin_port;
    udpHdr->destPort = destAddr->sin_port;
    udpHdr->totalLength = HTONS(udpLen);
    udpHdr->totalChecksum = 0;

    iovec[numIovecs++] = {
        txRegisteredBuf->dmaBufferAddress,
        sizeof(EthernetHeader) + sizeof(IpHeader) + sizeof(UdpHeader)
    };

    uint8_t* txBufferTail = 
        reinterpret_cast<uint8_t*>(udpHdr) + sizeof(UdpHeader);

    // If header is in the log memory that NIC has DMA access to, we don't
    // need to copy it over to txRegisteredBuf but we have to add a new iovec
    // for the header.
    const uintptr_t headerAddr =
        reinterpret_cast<const uintptr_t>(header);
    if (headerAddr >= logBase &&
        (headerAddr + headerLen) < (logBase + logBytes)) {

        iovec[numIovecs++] = {
            ef_memreg_dma_addr(
                &logMemoryReg, downCast<int>(headerAddr - logBase)),
            headerLen
        };
    } else {
        uint8_t* transportHdr = txBufferTail;
        memcpy(transportHdr, header, headerLen);
        iovec[numIovecs - 1].iov_len += headerLen;
        txBufferTail += headerLen;
    }

    // Ship the payload in iovecs here
    uint8_t* txBufferLead = txBufferTail;   
    while (payload && !payload->isDone()) {
        const uintptr_t payloadAddr =
            reinterpret_cast<const uintptr_t>(payload->getData());

        if (payloadAddr >= logBase && 
            (payloadAddr + payload->getLength()) < (logBase + logBytes)) {

            if (txBufferLead != txBufferTail) {
                iovec[numIovecs++] = {
                    txRegisteredBuf->dmaBufferAddress + 
                        (txBufferLead - txRegisteredBuf->dmaBuffer),
                    downCast<unsigned int>(txBufferTail - txBufferLead)
                };
                txBufferLead = txBufferTail;
            }

            iovec[numIovecs++] = {
                ef_memreg_dma_addr(&logMemoryReg, 
                    downCast<int>(payloadAddr - logBase)),
                payload->getLength()
            };
        } else {
            memcpy(txBufferTail, payload->getData(), payload->getLength());
            txBufferTail += payload->getLength();
        }
        payload->next();
    }
    
    if (txBufferLead != txBufferTail) {
        iovec[numIovecs++] = {
            txRegisteredBuf->dmaBufferAddress + 
                (txBufferLead - txRegisteredBuf->dmaBuffer),
            downCast<unsigned int>(txBufferTail - txBufferLead)
        };
        txBufferLead = txBufferTail;
    }

    // Resolve recipient mac address
    const uint8_t *recvMac = recipientAddress->macAddress->address;
    if (!recipientAddress->macProvided) {

        // No mac has been provided, so we need to resolve it through ARP
        // lookup.
        if (arpCache->arpLookup(ipHdr->ipDestAddress, ethHdr)) {

            // By invoking ef_vi_transmit() the descriptor that describes the
            // packet is queued in the transmit ring, and a doorbell is rung to
            // inform the adapter that the transmit ring is non-empty. Later on
            // in Poller::poll() we fetch notifications off of the event queue
            // that implies which packet transmit is completed.
            ef_vi_transmitv(&virtualInterface, iovec, numIovecs,
                txRegisteredBuf->id);
        } else {

            // Could not resolve mac from the local ARP cache or kernel ARP
            // cache. This probably means we don't have access to kernel ARP
            // cache or kernel ARP cache times out pretty quickly or the ARP
            // packets takes a long time to travel in network. Any ways, we
            // return immediately without sending the packet out and let the
            // higher level transport code to take care of retransmission later.
            txBufferPool->prependToList(txRegisteredBuf);
            in_addr destInAddr = {ipHdr->ipDestAddress};
            LOG(WARNING, "Was not able to resolve the MAC address for the"
                " destined to %s", inet_ntoa(destInAddr));
        }
    } else {
        memcpy(ethHdr->destAddress, recvMac, sizeof(ethHdr->destAddress));
        //LOG(NOTICE, "%s", (ethernetHeaderToStr(ethHdr)).c_str());
        //LOG(NOTICE, "%s", (ipHeaderToStr(ipHdr)).c_str());
        //LOG(NOTICE, "%s", (udpHeaderToStr(udpHdr)).c_str());
        ef_vi_transmitv(&virtualInterface, iovec, numIovecs,
            txRegisteredBuf->id);
    }
}

/**
 * This method fetches the notifications off of the event queue on the 
 * NIC. The received packets are then forwarded to be handled by 
 * transport code and transmitted buffers will be returned to the transmit
 * buffer pool. This function is always called from dispatch loop.
 * See docs in the ``Driver'' class.
 */
void
SolarFlareDriver::Poller::poll()
{
    assert(driver->context->dispatch->isDispatchThread());

    // To receive packets, descriptors each identifying a buffer,
    // are queued in the RX ring. The event queue is a channel
    // from the adapter to software which notifies software when
    // packets arrive from the network, and when transmits complete
    // (so that the buffers can be freed or reused).
    // events[] array contains the notifications that are fetched off
    // of the event queue on NIC and correspond to this VI of this driver.
    // Each member of the array could be a transmit completion notification
    // or a notification to a received packet or an error that happened
    // in receive or transmits.
    ef_event events[EF_VI_EVENT_POLL_NUM_EVS];

    // Contains the id of packets that have been successfully transmitted
    // or failed. It will be used for fast access to the packet buffer
    // that has been used for that transmission.
    ef_request_id packetIds[EF_VI_TRANSMIT_BATCH];

    // The application retrieves these events from event queue by calling
    // ef_event_poll().
    int eventCnt = ef_eventq_poll(&driver->virtualInterface, events,
                                  sizeof(events)/sizeof(events[0]));
    for (int i = 0; i < eventCnt; i++) {
        LOG(DEBUG, "%d events polled off of NIC", eventCnt);
        int numCompleted = 0;
        int txErrorType = 0;
        int rxDiscardType = 0;
        switch (EF_EVENT_TYPE(events[i])) {

            // A new packet has been received.
            case EF_EVENT_TYPE_RX:

                // The SolarFlare library provides function functions
                // EF_EVENT_RX_RQ_ID and EF_EVENT_RX_BYTES to find the id and
                // length of the received packet from the notification that's
                // been polled off of the event queue.
                driver->handleReceived(EF_EVENT_RX_RQ_ID(events[i]),
                                       EF_EVENT_RX_BYTES(events[i]));
                driver->numRxPktsToPost++;
                break;

            // A packet transmit has been completed
            case EF_EVENT_TYPE_TX:
                 numCompleted =
                    ef_vi_transmit_unbundle(&driver->virtualInterface,
                                            &events[i],
                                            packetIds);
                for (int j = 0; j < numCompleted; j++) {
                    driver->txBufferPool->prependToListById(packetIds[j]);
                }
                break;

            // A packet has been received but it must be discarded because
            // either its erroneous or is not targeted for this driver.
            case EF_EVENT_TYPE_RX_DISCARD:

                // This "if" statement will be taken out from the final code.
                // Currently serves for the cases that we might specify
                // an arbitrary mac address for string locator (something
                // other than the actual mac address of the SolarFlare card)
                if (EF_EVENT_RX_DISCARD_TYPE(events[i])
                             == EF_EVENT_RX_DISCARD_OTHER) {
                    driver->handleReceived(
                        EF_EVENT_RX_DISCARD_RQ_ID(events[i]),
                        EF_EVENT_RX_DISCARD_BYTES(events[i]));
                } else {
                    rxDiscardType = EF_EVENT_RX_DISCARD_TYPE(events[i]);
                    LOG(NOTICE, "Received discarded packet of type %d (%s)",
                        rxDiscardType,
                        driver->rxDiscardTypeToStr(rxDiscardType).c_str());

                    // The buffer for the discarded received packet must be
                    // returned to the receive free list
                    int packetId = EF_EVENT_RX_DISCARD_RQ_ID(events[i]);
                    driver->rxBufferPool->prependToListById(packetId);
                }
                driver->numRxPktsToPost++;
                break;

            // Error happened in transmitting a packet.
            case EF_EVENT_TYPE_TX_ERROR:
                txErrorType = EF_EVENT_TX_ERROR_TYPE(events[i]);
                LOG(WARNING, "TX error type %d (%s) happened!",
                    txErrorType,
                    driver->txErrTypeToStr(txErrorType).c_str());
                break;
            // Type of the event does not match to any above case statements.
            default:
                LOG(WARNING, "Unexpected event for event id %d", i);
                break;
        }
    }

    // At the end of the poller loop, we will push back a number of buffers to
    // the RX ring equal to the number of buffers that we have just freed.
    int actualNumPosted = driver->refillRxRing(driver->numRxPktsToPost);
    driver->numRxPktsToPost -= actualNumPosted;
}

/**
 * A helper method for the packets that arrive on the NIC. It passes the packet 
 * payload to the next layer in transport software (eg. FastTransport)
 * 
 * \param packetId
 *      This is the id of the packetBuff within the received memory chunk.
 *      This is used for fast calculation of the address of the packet within
 *      that memory chunk.
 * \param packetLen
 *      The actual length in bytes of the packet that's been received in NIC.
 *      
 */
void
SolarFlareDriver::handleReceived(int packetId, int packetLen)
{
    assert(downCast<uint32_t>(packetLen) >=
                        rxPrefixLen + sizeof(EthernetHeader) +
                        sizeof(IpHeader) + sizeof(UdpHeader));
    assert(downCast<uint32_t>(packetLen) < ETHERNET_MAX_DATA_LEN);

    struct PacketBuff* packetBuff = rxBufferPool->getBufferById(packetId);
        
    char* ethPkt = reinterpret_cast<char*>(packetBuff->dmaBuffer) + rxPrefixLen;
    uint32_t totalLen = packetLen - rxPrefixLen;
    EthernetHeader* ethHdr = reinterpret_cast<EthernetHeader*>(ethPkt);
    IpHeader* ipHdr = reinterpret_cast<IpHeader*>(
                      reinterpret_cast<char*>(ethHdr)
                      + sizeof(EthernetHeader));

    UdpHeader* udpHdr = reinterpret_cast<UdpHeader*>(
                            reinterpret_cast<char*>(ipHdr)
                            + sizeof(IpHeader));

    //LOG(NOTICE, "%s", ethernetHeaderToStr(ethHdr).c_str());
    //LOG(NOTICE, "%s",ipHeaderToStr(ipHdr).c_str());
    //LOG(NOTICE, "%s",udpHeaderToStr(udpHdr).c_str());

    //find mac, ip and port of the sender
    uint8_t* mac = ethHdr->srcAddress;
    uint32_t ip = ntohl(ipHdr->ipSrcAddress);
    uint16_t port = NTOHS(udpHdr->srcPort);

    Received received; 
    received.payload =  ethPkt + ETH_DATA_OFFSET;
    received.len = 
        downCast<uint32_t>(NTOHS(udpHdr->totalLength) -
        downCast<uint16_t>(sizeof(UdpHeader)));
    received.driver = this;
    received.sender = packetBuff->solarFlareAddress.construct(ip, port, mac);

    if (received.len != (totalLen - ETH_DATA_OFFSET)) {
        LOG(WARNING, "total payload bytes received is %u,"
            " but UDP payload length is %u bytes",
            (totalLen - ETH_DATA_OFFSET), received.len);
    }
    (*incomingPacketHandler)(&received);

    buffsNotReleased++;
}

/**
 * Returns the string equivalent of error type of a discarded received packet.
 *
 * \param type
 *      The numeric value of RX discard type.
 * \return
 *      The string equivalent of a numeric value for discard type.  
 */
const string
SolarFlareDriver::rxDiscardTypeToStr(int type)
{
    switch (type) {

        // Checksum value in IP or UDP header is erroneous.
        case EF_EVENT_RX_DISCARD_CSUM_BAD:
            return string("EF_EVENT_RX_DISCARD_CSUM_BAD");

        // The packet is a multicast packet that is not targeted to this driver.
        case EF_EVENT_RX_DISCARD_MCAST_MISMATCH:
            return string("EF_EVENT_RX_DISCARD_MCAST_MISMATCH");

        // Error in CRC checksum of the Ethernet frame.
        case EF_EVENT_RX_DISCARD_CRC_BAD:
            return string("EF_EVENT_RX_DISCARD_CRC_BAD");

        // Ethernet frame truncated and shorter than expected.
        case EF_EVENT_RX_DISCARD_TRUNC:
            return string("EF_EVENT_RX_DISCARD_TRUNC");

        // The buffer owner id of this event does not match the one for this
        // driver meaning that this event was delivered to this driver by
        // mistake.
        case EF_EVENT_RX_DISCARD_RIGHTS:
            return string("EF_EVENT_RX_DISCARD_RIGHTS");

        // Unexpected error happened for the current event. The current event
        // is not what it is expected to be which means that an event is lost.
        case EF_EVENT_RX_DISCARD_EV_ERROR:
            return string("EF_EVENT_RX_DISCARD_EV_ERROR");

        // Any other type of RX error not covered in above cases.
        default:
            return string("EF_EVENT_RX_DISCARD_OTHER");
    }
}

/**
 * Returns the string equivalent of error that happened in transmitting a
 * packet.
 * \param type
 *      The numeric value of TX error type.
 * \return
 *      A string describing the type of error happened in transmit.
 */
const string
SolarFlareDriver::txErrTypeToStr(int type)
{
    switch (type) {

        // The buffer owner id of this packet doesn't match to this driver.
        case EF_EVENT_TX_ERROR_RIGHTS:
            return string("EF_EVENT_TX_ERROR_RIGHTS");

        // Transmit wait queue overflow.
        case EF_EVENT_TX_ERROR_OFLOW:
            return string("EF_EVENT_TX_ERROR_OFLOW");

        // The transmit packet is too big to send.
        case EF_EVENT_TX_ERROR_2BIG:
            return string("EF_EVENT_TX_ERROR_2BIG");

        // Bus error happened while transmitting this packet.
        case EF_EVENT_TX_ERROR_BUS:
            return string("EF_EVENT_TX_ERROR_BUS");

        // None of the errors above.
        default:
            return string("NO_TYPE_SPECIFIED_FOR_THIS_ERR");
    }
}

/**
 * See docs in the ``Driver'' class.
 */
string
SolarFlareDriver::getServiceLocator()
{
    return localStringLocator;
}
} // end RAMCloud
