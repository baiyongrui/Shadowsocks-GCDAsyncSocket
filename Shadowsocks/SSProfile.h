/*
 *  SSProfile.h
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

#import <Foundation/Foundation.h>

@interface SSProfile : NSObject

// Required
@property (strong,nonatomic) NSString *remoteHost;
@property (nonatomic) uint16_t remotePort;
@property (strong,nonatomic) NSString *method;
@property (strong,nonatomic) NSString *password;
@property (nonatomic) uint16_t localPort;
@property (nonatomic) NSTimeInterval timeout;

// Optional
@property (nonatomic) BOOL isFastOpen;
@property (nonatomic) int verbose;


+ (instancetype)defaultProfile;

- (BOOL)isEqualToProfile:(SSProfile *)profile;

@end
