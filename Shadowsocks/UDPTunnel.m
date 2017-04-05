//
//  UDPTunnel.m
//  Shadowsocks
//
//  Created by 白永睿 on 2017/4/3.
//
//

#import "UDPTunnel.h"

#include <arpa/inet.h>

static dispatch_queue_t socketQueue;

@interface UDPTunnel () <GCDAsyncUdpSocketDelegate>

@end


@implementation UDPTunnel

- (instancetype)initWithDstAddr:(in_addr_t)dstAddr dstPort:(uint16_t)dstPort srcAddr:(in_addr_t)srcAddr srcPort:(uint16_t)srcPort {
    if ((self = [super init])) {
        _sock = [[GCDAsyncUdpSocket alloc] initWithDelegate:self delegateQueue:socketQueue];
        NSError *error;
        [_sock bindToPort:0 error:&error];
        if (!error) {
            _dstAddr = dstAddr;
            _dstPort = dstPort;
            _srcAddr = srcAddr;
            _srcPort = srcPort;
            _lastActivityTime = [NSDate date].timeIntervalSince1970;
            
            
            [_sock beginReceiving:NULL];
        }
    }
    return self;
}

- (void)processUDPData:(NSData *)data {
    struct in_addr dstAddr = {_dstAddr};

    [_sock sendData:data toHost:[NSString stringWithUTF8String:inet_ntoa(dstAddr)] port:ntohs(_dstPort) withTimeout:30 tag:0];
}

- (void)closeTunnel {
    _delegate = nil;
    [_sock setDelegate:nil];
    [_sock close];
    _sock = nil;
}

+ (void)initDispatchQueue {
    if (socketQueue == NULL)
        socketQueue = dispatch_queue_create("UDPTunnel Queue", NULL);
}



- (void)udpSocket:(GCDAsyncUdpSocket *)sock didReceiveData:(NSData *)data fromAddress:(NSData *)address withFilterContext:(id)filterContext {
    [self.delegate udpTunnel:self didReadData:data fromAddress:address];
}

@end
