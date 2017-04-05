//
//  TCPTunnel.h
//  Shadowsocks
//
//  Created by 白永睿 on 2017/4/2.
//
//

#import <Foundation/Foundation.h>
#import <CocoaAsyncSocket/GCDAsyncSocket.h>

#import "SSProfile.h"

#include "crypto.h"


@class TCPTunnelRemote;
@class TCPTunnel;

@protocol TCPTunnelDelegate <NSObject>

@required
- (void)tcpTunnel:(TCPTunnel *)tunnel didReadData:(NSData *)data;
- (void)tcpTunnelDidClose:(TCPTunnel *)tunnel;

@end

@interface TCPTunnel : NSObject {
@public
    cipher_ctx_t *_e_ctx;
    cipher_ctx_t *_d_ctx;
    buffer_t *_buf;
    buffer_t *_abuf;
    
    int _stage;
    TCPTunnelRemote *_remote;
}

@property (nonatomic) int tunTCPSocketIdentity;
@property (nonatomic) in_addr_t dstAddr;
@property (nonatomic) uint16_t dstPort;

@property (nonatomic, weak) id <TCPTunnelDelegate> delegate;
@property (nonatomic) BOOL isClosed;

- (void)processTCPData:(NSData *)data;
- (void)closeTunnel;

- (instancetype)initWithProfile:(SSProfile *)profile tcpSocketIdentity:(int)identity dstAddr:(in_addr_t)dstAddr dstPort:(uint16_t)dstPort;

+ (void)initDispatchQueue;

@end

@interface TCPTunnelRemote : NSObject {
@public
    GCDAsyncSocket *_sock;
    int _direct;
    buffer_t *_buf;
    
    TCPTunnel *_server;
    NSString *_host;
    NSUInteger _port;
    
    BOOL _isConnecting;
}

- (instancetype)initWithHost:(NSString *)host port:(NSUInteger)port;

@end
