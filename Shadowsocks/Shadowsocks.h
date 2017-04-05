/*
 *  Shadowsocks.h
 *  Shadowsocks-GCDAsyncSocket
 *
 *  Copyright © 2017 BaiYongrui.
 
 *  This file is part of Shadowsocks-GCDAsyncSocket.
 *
 *  Shadowsocks-GCDAsyncSocket is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Shadowsocks-GCDAsyncSocket is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Shadowsocks-GCDAsyncSocket.  If not, see <http://www.gnu.org/licenses/>.
 */

#import <Cocoa/Cocoa.h>

//! Project version number for Shadowsocks.
FOUNDATION_EXPORT double ShadowsocksVersionNumber;

//! Project version string for Shadowsocks.
FOUNDATION_EXPORT const unsigned char ShadowsocksVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <Shadowsocks/PublicHeader.h>
#import <Shadowsocks/SSLocal.h>
#import <Shadowsocks/SSProfile.h>
#import <Shadowsocks/TCPTunnel.h>
#import <Shadowsocks/UDPTunnel.h>
