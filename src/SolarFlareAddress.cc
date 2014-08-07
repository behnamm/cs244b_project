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
#include "SolarFlareAddress.h"

namespace RAMCloud
{

/**
 * Construct an SolarFlareAddress from the information in a ServiceLocator.
 * \param serviceLocator
 *      The "host" and "port" options describe the desired address.
 */
SolarFlareAddress::SolarFlareAddress(const ServiceLocator& serviceLocator)
    : ipAddress(serviceLocator)
    , macAddress(serviceLocator.getOption<const char*>("mac",
        "00:00:00:00:00:00"))
{}

/**
 * Create a new address from 6 bytes mac address, 32 bits ip address and 16
 * bits of the ip port.
 * \param mac 
 *      The raw bytes of mac address.
 * \param ip
 *      32 bit ip address generated by putting together the 4 bytes of the
 *      ip address in host order.
 * \param port
 *      16 bit ip port generated by putting together the 2 bytes of the
 *      ip port in host order.
 */
SolarFlareAddress::SolarFlareAddress(const uint8_t mac[6]
                                     , const uint32_t ip
                                     , const uint16_t port)

    : ipAddress(ip, port)
    , macAddress(mac)
{}

/**
 * Return a string describing the contents of this SolarFlareAddress (host
 * mac, ip address & port).
 */
string SolarFlareAddress::toString() const
{
    return string("mac=") + macAddress.toString()
           + string(", host=") + ipAddress.toString();
}

} // end RAMCloud
