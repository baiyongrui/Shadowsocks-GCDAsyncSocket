//
//  UDPTunnel.h
//  Shadowsocks
//
//  Created by 白永睿 on 2017/4/3.
//
//

#import <Foundation/Foundation.h>
#import <CocoaAsyncSocket/GCDAsyncUdpSocket.h>

#define MAX_SESSION_LIMIT 20

@class UDPTunnel;

@protocol UDPTunnelDelegate <NSObject>

@required
- (void)udpTunnel:(UDPTunnel *)tunnel didReadData:(NSData *)data fromAddress:(NSData *)address;

@end

@interface UDPTunnel : NSObject

@property (nonatomic, weak) id <UDPTunnelDelegate> delegate;

@property (nonatomic) in_addr_t dstAddr;
@property (nonatomic) uint16_t dstPort;   // key
@property (nonatomic) in_addr_t srcAddr;
@property (nonatomic) uint16_t srcPort;
@property (nonatomic) NSTimeInterval lastActivityTime;

@property (nonatomic, strong) GCDAsyncUdpSocket *sock;

- (instancetype)initWithDstAddr:(in_addr_t)dstAddr dstPort:(uint16_t)dstPort srcAddr:(in_addr_t)srcAddr srcPort:(uint16_t)srcPort;

- (void)processUDPData:(NSData *)data;

- (void)closeTunnel;

+ (void)initDispatchQueue;

@end
