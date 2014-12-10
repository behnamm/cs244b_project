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

// Attention: this test only runs if you have SolarFalre NIC installed on
// your machine. Also this test only runs if the NIC of the machine that is
// running this test is connected to a switch.
class SolarFlareDriverTest : public::testing::Test {
  public:
    Context context;
    SolarFlareDriverTest()
        :context()
    {}

    const char* waitForMessage(MockFastTransport* transport) {
        for (int i = 0; i < 1000; i++) {
            context.dispatch->poll();
            if (transport->packetData.size() != 0) {
                return transport->packetData.c_str();
            }
            usleep(1000);
        }
        return "No packet received!";
    }
  private:
    DISALLOW_COPY_AND_ASSIGN(SolarFlareDriverTest);
};

TEST_F(SolarFlareDriverTest, basics) {
    ServiceLocator serverLocator("fast+sf:mac=00:0F:53:0D:1E:30,"
        "host=10.10.10.10,port=1415");
    SolarFlareDriver* serverDriver =
        new SolarFlareDriver(&context, &serverLocator);
    MockFastTransport serverTransport(&context, serverDriver);

    ServiceLocator clientLocator("fast+sf:mac=00:0F:53:0D:1E:30,"
        "host=10.10.10.10,port=1416");
    SolarFlareDriver* clientDriver =
        new SolarFlareDriver(&context, &clientLocator);
    MockFastTransport clientTransport(&context, clientDriver);

    Buffer buffer;
    const char* message = "Howdy! I'm testing the driver.";
    buffer.appendExternal(message, downCast<uint32_t>(strlen(message)));
    Buffer::Iterator payload(&buffer);
    Driver::Address* serverAddress = clientDriver->newAddress(serverLocator);
    clientDriver->sendPacket(serverAddress, "header:", 7, &payload);
    EXPECT_STREQ(message,
                 waitForMessage(&serverTransport));
    delete serverAddress;
}

} // namespace RAMCloud
