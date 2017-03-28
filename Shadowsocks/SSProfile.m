/*
 *  SSProfile.m
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

#import "SSProfile.h"

@implementation SSProfile

+ (instancetype)defaultProfile {
    SSProfile *profile = [[SSProfile alloc] init];
    profile.timeout = 60;
    profile.localPort = 1086;
    
    return profile;
}

- (BOOL)isEqualToProfile:(SSProfile *)profile {
    return [self.remoteHost isEqualToString:profile.remoteHost] &&
    self.remotePort == profile.remotePort &&
    [self.method isEqualToString:profile.method] &&
    [self.password isEqualToString:profile.password] &&
    self.localPort == profile.localPort &&
    self.timeout == profile.timeout &&
    self.isFastOpen == profile.isFastOpen &&
    self.verbose == profile.verbose;
}

@end
