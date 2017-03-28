/*
 *  SSLocal.h
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
#import "SSProfile.h"

#include "crypto.h"
#include "common.h"

@class GCDAsyncSocket;

@class Remote;

@interface Server : NSObject {
    @public
    cipher_ctx_t *_e_ctx;
    cipher_ctx_t *_d_ctx;
    buffer_t *_buf;
    buffer_t *_abuf;
    
    GCDAsyncSocket *_sock;
    int _stage;
    Remote *_remote;
}

- (instancetype)initWithSock:(GCDAsyncSocket *)sock;

@end

@interface Remote : NSObject {
    @public
    GCDAsyncSocket *_sock;
    int _direct;
    int _addr_len;
    uint32_t _counter;
    buffer_t *_buf;
    
    Server *_server;
    NSString *_host;
    NSUInteger _port;
    
    BOOL _isConnecting;
}

- (instancetype)initWithHost:(NSString *)host port:(NSUInteger)port;

@end

@interface SSLocal : NSObject

- (BOOL)startSSLocalServerWithProfile:(SSProfile *)profile;
- (void)stopSSLocalServer;

@end
