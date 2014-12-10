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

#ifndef RAMCLOUD_SOLARFLAREDRIVER_H
#define RAMCLOUD_SOLARFLAREDRIVER_H

#include <netinet/in.h>
#include <etherfabric/memreg.h>
#include <etherfabric/pd.h>
#include <etherfabric/vi.h>

#include "ArpCache.h"
#include "Common.h"
#include "Dispatch.h"
#include "Driver.h"
#include "EthernetUtil.h"
#include "ObjectPool.h"
#include "SolarFlareAddress.h"
#include "ServiceLocator.h"
#include "ShortMacros.h"
#include "Transport.h"
#include "Tub.h"

namespace RAMCloud {

using namespace EthernetUtil; //NOLINT

/**
* A simple driver for SolarFlare NICs to send and receive unreliable datagrams. 
* This driver does not provide any reliability guarantees and intended to be
* used with higher level transport code (eg FastTransport)
* See Driver.h for some more details.
*/

/// This macro forces the compiler to align allocated memory to the cash line
/// size. This is necessary as a performance boost for the data portion of
/// packet buffers.
#define CACHE_ALIGN  __attribute__((aligned(CACHE_LINE_SIZE)))

class SolarFlareDriver : public Driver {
  public:
    explicit SolarFlareDriver(Context* context,
                              const ServiceLocator* localServiceLocator);
    virtual ~SolarFlareDriver();
    virtual void connect(IncomingPacketHandler* incomingPacketHandler);
    virtual void disconnect();
    virtual uint32_t getMaxPacketSize();
    virtual void release(char* payload);
    virtual void sendPacket(const Driver::Address* recipient,
                            const void* header,
                            const uint32_t headerLen,
                            Buffer::Iterator *payload);
    virtual string getServiceLocator();
    virtual Driver::Address* newAddress(const ServiceLocator& serviceLocator) {
        return new SolarFlareAddress(serviceLocator);
    }

    /**
     * A helper function for finding the maximum possible size (in bytes) of RPC
     * objects that can be shipped in one single request to a server.
     * 
     * \return
     *      size of the largest possible RPC defined in RAMCloud.
     */
    uint32_t getMaxRpcLen() {
        return Transport::MAX_RPC_LEN;
    }

    /// Defines the total number of buffers that the driver is allowed to pack
    /// in TX ring. Maximum value for this constant is 4096. Larger values
    /// increases the latency for small objects.
    static const uint32_t TX_RING_CAP = 2048;

    /// The size, in bytes, of the packet buffer for both RX and TX ring.
    /// As per SolarFlare recommendation, this should be equal to 2048.
    static const uint32_t ADAPTER_BUFFER_SIZE = 2048;

    /// Defines the total number of buffers that the driver is allowed to pack
    /// into RX ring. Maximum value for this constant is 4096. Larger values
    /// increases the latency for small objects.
    static const uint32_t RX_RING_CAP = 2048;

    /// Size of the event queue on the adapter.
    static const uint32_t EF_VI_EVENT_POLL_NUM_EVS = 128;

    /// Due to performance considerations, we refill RX ring in a batch of
    /// size equal to below constant.
    static const uint32_t RX_REFILL_BATCH_SIZE = 32;

    /// Offset of payload data portion of an Ethernet frame measured from first
    /// byte of Ethernet header. We assume the Ethernet frame contains IP header
    /// and UDP header right after Ethernet header and then comes the payload
    /// data.
    static const uint32_t ETH_DATA_OFFSET =
        sizeof(EthernetHeader) + sizeof(IpHeader) + sizeof(UdpHeader);

     /**
     * See docs in the ``Driver'' class.
     */
    virtual void registerMemory(void* base, size_t bytes) {
        int rc =
            ef_memreg_alloc(&logMemoryReg, driverHandle, &protectionDomain,
            driverHandle, base, downCast<int>(bytes));
        if (rc < 0) {
            DIE("Failed to register memory region at %p and size"
                " %Zd bytes for SolarFlare NIC", base, bytes);
        }
        LOG(NOTICE, "Registered memory at %p and size %Zd bytes to"
            " SolarFlare NIC", base, bytes);
        logBase = reinterpret_cast<uintptr_t>(base);
        logBytes = bytes;
    }

    /**
     * Defines a memory buffer that is to be pushed into the RX or TX ring
     * of the SolarFlare adapter for receiving/transmitting packets. Each
     * PacketBuff must be withing the region of memory that SolarFlare NIC has
     * DMA access to it.
     */
     struct PacketBuff {
        struct PacketBuff* next;

        /// Holds the DMA address to the beginning of the data array
        /// (dmaBuffer[]) of this buffer.
        ef_addr dmaBufferAddress;

        /// This is the id that we will pass it to the RX/TX ring and the NIC
        /// will return it to us in events. It helps to easily identify this
        /// packet buffer among all the PacketBuff registered to the NIC.
        int id;

        /// For every RX packet, this address will be constructed from senders
        /// information and will be passed to the higher level transport code
        /// (eg. FastTransport). The reply packets will be sent to this address.
        /// We keep the address object for an RX packet in the excess space
        /// of this buffer object for efficient use of the extra space.
        Tub<SolarFlareAddress> solarFlareAddress;

        /// The actual packet content in this buffer starts at this address.
        /// It's cache aligned for performance optimization.
        uint8_t dmaBuffer[0] CACHE_ALIGN;
    };

    /**
     * A container for a list (pool) of packet buffers that are registered to
     * the NIC and ready to be pushed to RX or TX ring. Provides methods for
     * fast accessing PacketBuffs, getting free and ready to use packetBuffs or
     * retrieving the packets and putting them back into the container after
     * they are unbundled from RX/TX ring.
     */
    class RegisteredBuffs {
      public:
        RegisteredBuffs(int bufferSize, int numBuffers,
            SolarFlareDriver* driver);
        ~RegisteredBuffs() {
            free(memoryChunk);
            ef_memreg_free(&registeredMemRegion, driver->driverHandle);

        }

        void prependToList(PacketBuff* packetBuff);
        void prependToListById(int packetId);
        PacketBuff* popFreeBuffer();
        PacketBuff* getBufferById(int packetId);

      PRIVATE:

        /// Address of the first byte of the memory region that is registered to
        /// the NIC for DMA access and has been subdivided into packet buffers
        /// in this container.
        char* memoryChunk;

        /// A data struct that contains DMA addresses of memory pages within the
        /// region of memory that is registered to the NIC container.
        ef_memreg registeredMemRegion;

        /// Total size in bytes of each  packet buffer in the list.
        int bufferSize;

        /// Total number of buffers in the list.
        int numBuffers;

        /// Address of the first free to use buffer in the list (head of the
        /// list) that is ready to be pushed to TX or RX ring.
        PacketBuff* freeBufferList;

        /// Pointer to the driver that owns this object.
        SolarFlareDriver* driver;
        DISALLOW_COPY_AND_ASSIGN(RegisteredBuffs);
    };

  PRIVATE:
    friend class RegisteredBuffs;

    /// Shared RAMCloud information.
    Context* context;

    /// Used to resolve destination mac address of outgoing packets
    Tub<ArpCache> arpCache;

    /// Keeps a copy of locator string for this SolarFlareDriver.
    string localStringLocator;

    /// Keeps a copy of the address object for this SolarFlareDriver.
    Tub<SolarFlareAddress> localAddress;

    /// Handler that is invoked whenever a new packet comes in.
    std::unique_ptr<IncomingPacketHandler> incomingPacketHandler;

    /// Handle to talk to SolarFlare NIC. Needed to allocate resources.
    ef_driver_handle driverHandle;

    /// Determines how memory should be protected for a Virtual Interfaces (VI).
    /// A protection domain is a collection of VIs and memory regions tied to
    /// single user interface.
    ef_pd protectionDomain;

    /// A Handle for the RAMCloud's log memory region that is registered to
    /// SolarFlare NIC. This will contain an array of DMA addresses of each page
    /// within that log memory region. It will be used for finding DMA addresses
    /// of memory addresses in that region for zero copy transmission from that
    /// address. It will be filled out by SolarFlareDriver::registerMemory func.
    ef_memreg logMemoryReg;

    /// The address to the beginning of RAMCloud's logMemory that is registered
    /// to SolarFlare NIC. Along with the logBytes defines the region of
    /// logMemory that SolarFlare NIC has DMA access to it and cad do zero copy
    /// transmission of packets from that region.
    uintptr_t logBase;

    /// The length in bytes of the logMemory region that is registered to
    /// SolarFlare NIC for zero copy transmission of packets.
    size_t logBytes;

    /// The Solarflare ef_vi API is a layer 2 API that grants an application
    /// direct (kernel bypassed) access to the Solarflare network adapter
    /// data path. ef_vi is the internal API for sending and receiving packets
    /// that do not require a POSIX socket interface.
    /// Users of ef_vi must first allocate a virtual interface (VI),
    /// encapsulated by the type "ef_vi". A VI includes: A receive descriptor
    /// ring (for receiving packets); A transmit descriptor ring (for sending
    /// packets); An event queue (to receive notifications from the hardware).
    ef_vi virtualInterface;

    /// A container that allocates some number of packet buffers that are
    /// registered to the NIC and will be used for transmitting packets.
    Tub<RegisteredBuffs> rxBufferPool;

    /// A container that allocates some number of packet buffers that are
    /// registered to the NIC and will be used for receiving packets.
    Tub<RegisteredBuffs> txBufferPool;

    /// Length in bytes of the prefix metadata that SolarFlare NIC adds to the
    /// beginning of each received packet. This is only used as an offset to
    /// beginning of the received packet buffer.
    int rxPrefixLen;

    /// Number of  packetBuffs that are allocated from rxBufferPool
    /// but not yet released by the higher level transport code (eg.
    /// FastTransport). At the end of the life of this driver, all buffers
    /// must have been released and therefore this variable must be zero.
    uint64_t buffsNotReleased;

    /// The number of packets for which we have called init() since the last
    /// time we called push(). In other words this is the number of packets
    /// that are prepared to be pushed to RX ring however not yet
    /// pushed as we want to push the in batch size of RX_REFILL_BATCH_SIZE
    /// for performance efficiency.
    uint64_t rxPktsReadyToPush;

    /// Tracks the difference between RX_RING_CAP and sum current fill level of
    /// the RX ring and number of RX buffers that are initialized by init()
    /// function but not yet pushed to the RX ring.
    int numRxPktsToPost;

    /// This file descriptor is only necessary when this driver is being used on
    /// a client side and no locator string has been provided.
    int fd;

    int refillRxRing(int numPktToPost);
    void handleReceived(int packetId, int packetLen);
    const string rxDiscardTypeToStr(int type);
    const string txErrTypeToStr(int type);

    /**
     * This is the object that polls the notifications from the event
     * queue of the NIC. Dispatch loop invokes the poll() function of this 
     * object to fetch the received packets and transmit notifications off 
     * of the NIC. 
     */
    class Poller : public Dispatch::Poller {
      public:
        explicit Poller(Context* context, SolarFlareDriver* solarFlareDriver)
            : Dispatch::Poller(context->dispatch, "SolarFlareDriver::Poller"),
            driver(solarFlareDriver) {}

        virtual void poll();
      private:

      /// Pointer to the driver corresponding to this Poller object.
      SolarFlareDriver* driver;
      DISALLOW_COPY_AND_ASSIGN(Poller);
    };
    friend class Poller;
    Tub<Poller> poller;
    static Syscall* sys;
    DISALLOW_COPY_AND_ASSIGN(SolarFlareDriver);
};
}//end RAMCloud
#endif //RAMCLOUD_SOLARFLAREDRIVER_H
