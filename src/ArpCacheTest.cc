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

#include <arpa/inet.h>
#include <ctype.h>
#include <fstream>
#include "TestUtil.h"
#include "EthernetUtil.h"
#include "MockSyscall.h"
#include "ArpCache.h"
#include "Tub.h"

namespace RAMCloud {

using namespace EthernetUtil; //NOLINT 

class ArpCacheTest :public ::testing::Test {
  public:
    Tub<ArpCache> arpCache;
    Context context;
    MockSyscall* mockSys;
    Syscall* savedSys;
    uint32_t localIp;
    string ifName;
    uint8_t remoteMac[6];
    uint32_t remoteIp;
    string exceptionMsg;

    ArpCacheTest()
        : arpCache()
        , context()
        , mockSys(NULL)
        , savedSys(NULL)
        , localIp(0)
        , ifName()
        , remoteMac()
        , remoteIp(0)
        , exceptionMsg()

    {
        mockSys = new MockSyscall();
        savedSys = ArpCache::sys;
        initialize(&remoteIp, ifName, remoteMac);
        arpCache.construct(&context, localIp, ifName.c_str());
    }

    ~ArpCacheTest()
    {
        delete mockSys;
    }

    /**
     * This method opens a stream file handle for the Kernel's arp table file
     * located at /proc/net/arp and parses the first entry on that table. It
     * extracts destination IP and MAC on that entry and saves them in remoteIp
     * and remoteMac parameters. These parameters will be used as reference
     * values for testing. It also initializes localIp value.
     */
    void initialize(uint32_t *remoteIp, string& ifName, uint8_t *remoteMac) {
        std::ifstream arpFile("/proc/net/arp");
        string line;
        getline(arpFile, line);
        getline(arpFile, line);
        std::vector<string> arpVec;
        while (line.size()) {
            for (size_t pos = 0; pos < line.size(); ++pos) {
                if (isspace(line[pos])) {
                    if (pos == 0) {
                        line.erase(0, 1);
                    } else {
                        arpVec.push_back(line.substr(0, pos));
                        line.erase(0, pos);
                    }
                    break;
                }

                if (pos == line.size() - 1) {
                    arpVec.push_back(line);
                    line.erase();
                }
            }
        }
        string ip = arpVec[0];
        string mac = arpVec[3];
        ifName = arpVec[5];
        *remoteIp = inet_addr(ip.c_str());

        unsigned int bytes[6];
        sscanf(mac.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", //NOLINT
            &bytes[0], &bytes[1], &bytes[2],
            &bytes[3], &bytes[4], &bytes[5]);
        for (uint32_t i = 0; i < 6; ++i)
            remoteMac[i] = downCast<uint8_t>(bytes[i]);

        ip = getLocalIp(ifName.c_str());
        localIp = inet_addr(ip.c_str());
    }

    /**
     * This method mocks a route file named fileName. This file is to be 
     * used for testing RouteTable class. The route file content that is mocked
     * by this method is as table below (in human readable format as terminal
     * command "route -n" prints on stdout): 
     * ------------------------------------------------------------------------
     * Destination     Gateway      Genmask         Flags Metric Ref  Use Iface
     * 192.168.100.0   0.0.0.0      255.255.255.0   U     0      0      0 eth2
     * 10.10.10.0      0.0.0.0      255.255.255.0   U     0      0      0 eth0
     * 171.66.3.0      0.0.0.0      255.255.255.0   U     0      0      0 eth3
     * 169.254.0.0     0.0.0.0      255.255.0.0     U     1002   0      0 eth0
     * 169.254.0.0     0.0.0.0      255.255.0.0     U     1004   0      0 eth2
     * 169.254.0.0     0.0.0.0      255.255.0.0     U     1005   0      0 eth3
     * 0.0.0.0         171.66.3.1   0.0.0.0         UG    0      0      0 eth3 
     * ------------------------------------------------------------------------
     * 
     * The ip parameter values in the file fileName will all be 32bit numbers in
     * network order format exactly similar to what it would appear in the
     * linux kernel route file located at /proc/net/route.  
     */
    void mockRouteFile(const char* fileName)
    {
        std::ofstream routeStream(fileName);
        routeStream.clear();

        routeStream
            <<
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\t"
                    "Metric\tMask\t\tMTU\tWindow\tIRTT   \n"
            <<
            "eth2\t0064A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0   \n"
            <<
            "eth0\t000A0A0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0   \n"
            <<
            "eth3\t000342AB\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0   \n"
            <<
            "eth0\t0000FEA9\t00000000\t0001\t0\t0\t1002\t0000FFFF\t0\t0\t0   \n"
            <<
            "eth2\t0000FEA9\t00000000\t0001\t0\t0\t1004\t0000FFFF\t0\t0\t0   \n"
            <<
            "eth3\t0000FEA9\t00000000\t0001\t0\t0\t1005\t0000FFFF\t0\t0\t0   \n"
            <<
            "eth3\t00000000\t010342AB\t0003\t0\t0\t0\t00000000\t0\t0\t0   ";
        routeStream.close();
    }

  PRIVATE:
    DISALLOW_COPY_AND_ASSIGN(ArpCacheTest);
};

TEST_F(ArpCacheTest, constructor_socketError) {
    ArpCache::sys = mockSys;
    mockSys->socketErrno = EPERM;
    try {
        ArpCache arpCache1(&context, localIp, ifName.c_str());
    } catch (Exception& e){
        exceptionMsg = e.message;
    }
    EXPECT_EQ(exceptionMsg, "ArpCache could not open a socket for resolving"
        " mac addresses!: Operation not permitted");
    mockSys->socketErrno = 0;
    ArpCache::sys = savedSys;
}

TEST_F(ArpCacheTest, constructor_failBind) {
    ArpCache::sys = mockSys;
    mockSys->bindErrno = EADDRINUSE;
    try {
        ArpCache arpCache1(&context, localIp, ifName.c_str());
    } catch (Exception& e){
        exceptionMsg = e.message;
    }
    in_addr local = {localIp};
    string expectedMsg = format("ArpCache could not bind the socket to %s: "
        "Address already in use", inet_ntoa(local));
    EXPECT_EQ(exceptionMsg, expectedMsg);
    mockSys->bindErrno = 0;
    ArpCache::sys = savedSys;
}

TEST_F(ArpCacheTest, basics_fromKernelCache) {

    TestLog::Enable _;
    EthernetHeader ethHdr;
    ethHdr.etherType = HTONS(EthernetType::IP_V4);
    EXPECT_TRUE(arpCache->arpLookup(remoteIp, &ethHdr));
    sockaddr_in remote;
    remote.sin_addr.s_addr = remoteIp;
    string logMsg = format("arpLookup: Resolved MAC address through kernel"
        " calls for host at %s!", inet_ntoa(remote.sin_addr));
    EXPECT_EQ(logMsg.c_str(), TestLog::get());
    EXPECT_EQ(ethHdr.destAddress[0], remoteMac[0]);
    EXPECT_EQ(ethHdr.destAddress[1], remoteMac[1]);
    EXPECT_EQ(ethHdr.destAddress[5], remoteMac[5]);
}

TEST_F(ArpCacheTest, basics_fromLocalCache) {

    TestLog::Enable _;
    EthernetHeader ethHdr;
    ethHdr.etherType = HTONS(EthernetType::IP_V4);
    EXPECT_TRUE(arpCache->arpLookup(remoteIp, &ethHdr));
    TestLog::reset();
    EXPECT_TRUE(arpCache->arpLookup(remoteIp, &ethHdr));

    sockaddr_in remote;
    remote.sin_addr.s_addr = remoteIp;
    string logMsg = format("arpLookup: Resolved MAC address for host %s through"
        " local cache!", inet_ntoa(remote.sin_addr));
    EXPECT_EQ(logMsg.c_str(), TestLog::get());
    EXPECT_EQ(ethHdr.destAddress[0], remoteMac[0]);
    EXPECT_EQ(ethHdr.destAddress[1], remoteMac[1]);
    EXPECT_EQ(ethHdr.destAddress[5], remoteMac[5]);
}

TEST_F(ArpCacheTest, testRouteTableConstructor) {
    const char* fileName = "/tmp/route";
    mockRouteFile(fileName);
    ArpCache::RouteTable routeTable2("eth2", fileName);
    ArpCache::RouteTable::RouteEntry& entry = routeTable2.routeVector[0];
    EXPECT_STREQ("eth2", entry.ifName);
    EXPECT_EQ(downCast<uint32_t>(0x0064A8C0), entry.destIpRange);
    EXPECT_EQ(downCast<uint32_t>(0x00000000), entry.gatewayIp);
    EXPECT_EQ(downCast<uint32_t>(0x00FFFFFF), entry.netMask);
    EXPECT_EQ(routeTable2.routeVector.size(), 2ul);

    ArpCache::RouteTable routeTable3("eth3", fileName);
    entry = routeTable3.routeVector[2];
    EXPECT_STREQ("eth3", entry.ifName);
    EXPECT_EQ(downCast<uint32_t>(0x00000000), entry.destIpRange);
    EXPECT_EQ(downCast<uint32_t>(0x010342AB), entry.gatewayIp);
    EXPECT_EQ(downCast<uint32_t>(0x00000000), entry.netMask);
    EXPECT_EQ(routeTable3.routeVector.size(), 3ul);

}

TEST_F(ArpCacheTest, getGatewayIp) {
    const char* fileName = "/tmp/route";
    mockRouteFile(fileName);
    ArpCache::RouteTable routeTable0("eth0", fileName);

    // gateway for 10.10.10.10 is itself (longest prefix match rule on route
    // table above)
    EXPECT_EQ(routeTable0.getGatewayIp(0x0A0A0A0A),
        downCast<uint32_t>(0x0A0A0A0A));

    // gateway for 10.10.11.10 is itself (no match for this IP in route table
    // above so the gateway must must be same as destIp)
    EXPECT_EQ(routeTable0.getGatewayIp(0x0A0B0A0A),
        downCast<uint32_t>(0x0A0B0A0A));

    ArpCache::RouteTable routeTable3("eth3", fileName);

    // gateway for 171.66.3.10 is itself (longest prefix match rule)
    EXPECT_EQ(routeTable3.getGatewayIp(0x0A0342AB),
        downCast<uint32_t>(0x0A0342AB));

    // gateway for 171.66.4.1 is at 171.66.3.1 (longest prefix match rule
    // on the last row of route table)
    EXPECT_EQ(routeTable3.getGatewayIp(0x010442AB),
        downCast<uint32_t>(0x010342AB));
}

}
