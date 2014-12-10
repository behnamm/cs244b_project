/* Copyright (c) 2014 Stanford University
 *
 * Permission to use, copy, modify, and distribute this software for any purpose
 * with or without fee is hereby granted, provided that the above copyright
 * notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR(S) DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
 * CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "TestUtil.h"
#include "MockFastTransport.h"
#include "SolarFlareDriver.h"

namespace RAMCloud {

using namespace EthernetUtil; //NOLINT

// Attention: this test only runs if you have SolarFalre NIC installed on
// your machine. Also this test only runs if the NIC of the machine that is
// running this test is connected to a switch.
class SolarFlareDriverTest : public::testing::Test {
  public:
    Context context;
    SolarFlareDriverTest()
        :context()
    {}

  private:
    DISALLOW_COPY_AND_ASSIGN(SolarFlareDriverTest);
};

TEST_F(SolarFlareDriverTest, sendPacket_zeroCopy) {
    SolarFlareDriver* serverDriver =
        new SolarFlareDriver(&context, NULL);
    ServiceLocator serverLocator(serverDriver->localStringLocator.c_str());

    SolarFlareDriver* clientDriver =
        new SolarFlareDriver(&context, NULL);
    Driver::Address* serverAddress = clientDriver->newAddress(serverLocator);
    uint32_t regBytes = 4096 * (1 << 4);
    void* memoryChunk = Memory::xmemalign(HERE, 4096, regBytes);
    clientDriver->registerMemory(memoryChunk, regBytes);

    // Testing for the case where header is not part of log memory.
    TestLog::Enable _;
    SolarFlareDriver::PacketBuff* pktBuff =
        clientDriver->txBufferPool->freeBufferList;
        string hdr = "header:";
    size_t l2AndL3HdrSize =
        sizeof(EthernetHeader) + sizeof(IpHeader) + sizeof(UdpHeader);
    size_t totalHdrSize = l2AndL3HdrSize + hdr.size();
    clientDriver->sendPacket(serverAddress, hdr.c_str(),
        downCast<uint32_t>(hdr.size()), NULL);
    string logStr =
        format("sendPacket: Total number of IoVecs are 1 |"
        " sendPacket: IoVec 0 starting at %lu and size %lu",
        pktBuff->dmaBufferAddress, totalHdrSize);
    EXPECT_EQ(logStr.c_str(), TestLog::get());

    // Testing for when header is part of log memory
    TestLog::reset();
    int offset = 100;
    char* header = reinterpret_cast<char*>(memoryChunk) + offset;
    uint32_t headerLen = 100;
    ef_addr headerDmaAddr =
        ef_memreg_dma_addr(&clientDriver->logMemoryReg, offset);
    pktBuff = clientDriver->txBufferPool->freeBufferList;
    clientDriver->sendPacket(serverAddress, header, headerLen, NULL);
    logStr =
        format("sendPacket: Total number of IoVecs are 2 |"
        " sendPacket: IoVec 0 starting at %lu and size %lu |"
        " sendPacket: IoVec 1 starting at %lu and size %u",
        pktBuff->dmaBufferAddress, l2AndL3HdrSize, headerDmaAddr, headerLen);
    EXPECT_EQ(logStr.c_str(), TestLog::get());

    // Testing for when there are three pieces of payload. First and last
    // pieces are not part of log memory but second piece is part of log memory.
    TestLog::reset();
    Buffer buffer;
    uint32_t dataSubLen = 300;
    char* nonRegisteredData1 = reinterpret_cast<char*>(malloc(dataSubLen));
    buffer.appendExternal(nonRegisteredData1, dataSubLen);

    uint32_t registeredDataOffset = 2 * offset + headerLen;
    char* registeredData =
        reinterpret_cast<char*>(memoryChunk) + registeredDataOffset;
    buffer.appendExternal(registeredData, dataSubLen);

    char* nonRegisteredData2 = reinterpret_cast<char*>(malloc(dataSubLen));
    buffer.appendExternal(nonRegisteredData2, dataSubLen);

    Buffer::Iterator payload(&buffer);
    pktBuff = clientDriver->txBufferPool->freeBufferList;
    clientDriver->sendPacket(serverAddress, header, headerLen, &payload);
    logStr =
        format("sendPacket: Total number of IoVecs are 5 |"
        " sendPacket: IoVec 0 starting at %lu and size %lu |"
        " sendPacket: IoVec 1 starting at %lu and size %u |"
        " sendPacket: IoVec 2 starting at %lu and size %u |"
        " sendPacket: IoVec 3 starting at %lu and size %u |"
        " sendPacket: IoVec 4 starting at %lu and size %u",
        pktBuff->dmaBufferAddress, l2AndL3HdrSize, headerDmaAddr, headerLen,
        pktBuff->dmaBufferAddress + l2AndL3HdrSize, dataSubLen,
        ef_memreg_dma_addr(&clientDriver->logMemoryReg, registeredDataOffset),
        dataSubLen,
        pktBuff->dmaBufferAddress + l2AndL3HdrSize + dataSubLen, dataSubLen);
    EXPECT_EQ(logStr.c_str(), TestLog::get());
    TestLog::reset();

    free(nonRegisteredData1);
    free(nonRegisteredData2);
    delete serverAddress;
    delete serverDriver;
    delete clientDriver;
    free(memoryChunk);
}

} // namespace RAMCloud
