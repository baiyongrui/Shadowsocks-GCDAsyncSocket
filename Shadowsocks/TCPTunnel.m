//
//  TCPTunnel.m
//  Shadowsocks
//
//  Created by 白永睿 on 2017/4/2.
//
//

#import "TCPTunnel.h"

#include <arpa/inet.h>

#include "shadowsocks-core/utils.h"
#include "socks5.h"
#include "http.h"
#include "tls.h"

#include <mbedtls/cipher.h>
#include <libsodium/sodium.h>


#define BUF_SIZE 2048

#define MAX_CONNECT_TIMEOUT 10

// Write tags
#define FAKE_REPLY 1
#define STREAM_WRITE 2
#define TFO_SYN 3

static dispatch_queue_t socketQueue;
static crypto_t *crypto;

// Profile
static BOOL fastOpen;
static NSTimeInterval timeout;

static int verbose;


@implementation TCPTunnel

+ (void)initDispatchQueue {
    if (socketQueue == NULL)
        socketQueue = dispatch_queue_create("TCPTunnel Queue", NULL);
}

- (instancetype)initWithProfile:(SSProfile *)profile tcpSocketIdentity:(int)identity dstAddr:(in_addr_t)dstAddr dstPort:(uint16_t)dstPort {
    if (self = [super init]) {
        _stage = STAGE_PARSE;
        _tunTCPSocketIdentity = identity;
        _dstAddr = dstAddr;
        _dstPort = dstPort;
        
        const char *method = [profile.method cStringUsingEncoding:NSUTF8StringEncoding];
        const char *password = [profile.password cStringUsingEncoding:NSUTF8StringEncoding];
        
        timeout = profile.timeout;
        fastOpen = profile.isFastOpen;
        verbose = profile.verbose;
        
        if (crypto == NULL) {
            NSLog(@"Initializing ciphers... %s", method);
            crypto = crypto_init(password, NULL, method);
            if (crypto == NULL)
                NSLog(@"Failed to init ciphers");
        }
        
        _remote = [[TCPTunnelRemote alloc] initWithHost:profile.remoteHost port:profile.remotePort];
        _remote->_server = self;
        
        _buf = ss_malloc(sizeof(buffer_t));
        _abuf = ss_malloc(sizeof(buffer_t));
        balloc(_buf, BUF_SIZE);
        balloc(_abuf, BUF_SIZE);
        
        _e_ctx = malloc(sizeof(cipher_ctx_t));
        _d_ctx = malloc(sizeof(cipher_ctx_t));
        crypto->ctx_init(crypto->cipher, _e_ctx, 1);
        crypto->ctx_init(crypto->cipher, _d_ctx, 0);
        
    }
    
    return self;
}

- (void)handle_stage_stream {
    
    // insert shadowsocks header
    if (!_remote->_direct) {
        
        int err = crypto->encrypt(_remote->_buf, _e_ctx, BUF_SIZE);
        
        if (err) {
            NSLog(@"invalid password or cipher");
            [self closeTunnel];
            return;
        }
        
        if (_abuf) {
            bprepend(_remote->_buf, _abuf, BUF_SIZE);
            bfree(_abuf);
            ss_free(_abuf);
            _abuf = NULL;
        }
    }
    
    if (![_remote->_sock isConnected] && !_remote->_isConnecting) {
        
        _remote->_buf->idx = 0;
        
        if (!fastOpen || _remote->_direct) {
            // connecting, wait until connected
            
            NSError *err = nil;
            _remote->_isConnecting = YES;
            
            if (![_remote->_sock connectToHost:_remote->_host onPort:_remote->_port withTimeout:MAX_CONNECT_TIMEOUT error:&err]) {  //timeout?
                NSLog(@"Error on remote connect: %@", err);
                [self closeTunnel];
                return;
            }
            
            NSData *sendData = [NSData dataWithBytes:_remote->_buf->data length:_remote->_buf->len];
            [_remote->_sock writeData:sendData withTimeout:20 tag:STREAM_WRITE];
            
        } else {
            //TCP_FASTOPEN
            NSData *sendData = [NSData dataWithBytes:_remote->_buf->data length:_remote->_buf->len];
            NSError *err = nil;
            _remote->_isConnecting = YES;
            if (![_remote->_sock connectToHost:_remote->_host onPort:_remote->_port withData:sendData tag:TFO_SYN timeout:MAX_CONNECT_TIMEOUT error:&err]) {
                NSLog(@"Error on remote connect: %@", err);
                [self closeTunnel];
                return;
            }
        }
        
        _remote->_buf->idx = 0;
        _remote->_buf->len = 0;
        
    } else {
        NSData *sendData = [NSData dataWithBytes:_remote->_buf->data length:_remote->_buf->len];
        [_remote->_sock writeData:sendData withTimeout:20 tag:STREAM_WRITE];
        
        _remote->_buf->idx = 0;
        _remote->_buf->len = 0;
    }
    
}

- (void)handle_stage_parse:(buffer_t *)buf{
    struct in_addr dstAddr = {_dstAddr};

    char host[257], ip[INET6_ADDRSTRLEN], port[16];
    
    buffer_t *abuf = _abuf;
    abuf->idx = 0;
    abuf->len = 0;
    
    // atyp = 1 for ipv4, only support ipv4 temporary
    int atyp = 1;
    abuf->data[abuf->len++] = atyp;
    
    size_t in_addr_len = sizeof(struct in_addr);

    uint16_t np = htons(_dstPort);
    memcpy(abuf->data + abuf->len, &dstAddr, in_addr_len);
    abuf->len += in_addr_len;
    
    memcpy(abuf->data + abuf->len, &np, 2);
    abuf->len += 2;
        
        //                if (acl || verbose) {
        if (verbose) {
            inet_ntop(AF_INET, (const void *)&dstAddr, ip, INET_ADDRSTRLEN);
            sprintf(port, "%d", _dstPort);
        }
    
    int sni_detected = 0;
    
    if (atyp == 1 || atyp == 4) {
        char *hostname = NULL;
//        uint16_t p = ntohs(*(uint16_t *)(abuf->data + abuf->len - 2));
        int ret    = 0;
        if (_dstPort == http_default_port)
            ret = parse_http_header(buf->data + 3 + abuf->len, buf->len - 3 - abuf->len, &hostname);
        else if (_dstPort == tls_default_port)
            ret = parse_tls_header(buf->data + 3 + abuf->len, buf->len - 3 - abuf->len, &hostname);
        if (ret == -1 && buf->len < BUF_SIZE) {
            _stage = STAGE_PARSE;
            return;     // need read more
        }
        else if (ret > 0) {
            sni_detected = 1;
            
            // Reconstruct address buffer
            abuf->len               = 0;
            abuf->data[abuf->len++] = 3;
            abuf->data[abuf->len++] = ret;
            memcpy(abuf->data + abuf->len, hostname, ret);
            abuf->len += ret;
//            p          = htons(p);
            memcpy(abuf->data + abuf->len, &np, 2);
            abuf->len += 2;
            
            //          if (acl || verbose) {
            if (verbose) {
                memcpy(host, hostname, ret);
                host[ret] = '\0';
            }
            
            ss_free(hostname);
        }
    }
    
    _stage = STAGE_STREAM;
    
//    buf->len -= (3 + abuf_len);
//    if (buf->len > 0) {
//        memmove(buf->data, buf->data + 3 + abuf_len, buf->len);
//    }
    
    if (verbose) {
        if (sni_detected || atyp == 3)
            NSLog(@"Connect to %s:%s", host, port);
        else if (atyp == 1)
            NSLog(@"Connect to %s:%s", ip, port);
        else if (atyp == 4)
            NSLog(@"Connect to [%s]:%s", ip, port);
    }
    
    //            if (acl) {
    //                int host_match = acl_match_host(host);
    //                int bypass = 0;
    //                if (host_match > 0)
    //                    bypass = 1;                 // bypass hostnames in black list
    //                else if (host_match < 0)
    //                    bypass = 0;                 // proxy hostnames in white list
    //                else {
    //                    int ip_match = acl_match_host(ip);
    //                    switch (get_acl_mode()) {
    //                        case BLACK_LIST:
    //                            if (ip_match > 0)
    //                                bypass = 1;               // bypass IPs in black list
    //                            break;
    //                        case WHITE_LIST:
    //                            bypass = 1;
    //                            if (ip_match < 0)
    //                                bypass = 0;               // proxy IPs in white list
    //                            break;
    //                    }
    //                }
    //
    //                if (bypass) {
    //                    if (verbose) {
    //                        if (sni_detected || atyp == 3)
    //                            LOGI("bypass %s:%s", host, port);
    //                        else if (atyp == 1)
    //                            LOGI("bypass %s:%s", ip, port);
    //                        else if (atyp == 4)
    //                            LOGI("bypass [%s]:%s", ip, port);
    //                    }
    //                    int err;
    //                    struct sockaddr_storage storage;
    //                    memset(&storage, 0, sizeof(struct sockaddr_storage));
    //
    //                        err = get_sockaddr(ip, port, &storage, 0, ipv6first);
    //                    if (err != -1) {
    //                        // Change host and port of TCPTunnnelRemote
    //                        remote = create_remote(server->listener, (struct sockaddr *)&storage);
    //                        if (remote != NULL)
    //                            remote->direct = 1;
    //                    }
    //                }
    //            }
    
    
    if (!_remote->_direct) {
        int err = crypto->encrypt(abuf, _e_ctx, BUF_SIZE);
        if (err) {
            NSLog(@"invalid password or cipher");
            [self closeTunnel];
            return;
        }
    }
    
    if (buf->len > 0) {
        memcpy(_remote->_buf->data, buf->data, buf->len);
        _remote->_buf->len = buf->len;
    }
    
    [self handle_stage_stream];
    
}

// Only called by closeTunnel:
- (void)free {
    
    if (_remote) {
        [_remote->_sock disconnect];
        _remote = nil;
    }
    
    if (_e_ctx) {
        crypto->ctx_release(_e_ctx);
        _e_ctx = nil;
    }
    if (_d_ctx) {
        crypto->ctx_release(_d_ctx);
        _d_ctx = nil;
    }
    if (_buf) {
        bfree(_buf);
        _buf = nil;
    }
    if (_abuf) {
        bfree(_abuf);
        _abuf = nil;
    }
    
}

// These methods were called by PacketTunnelProvider
- (void)processTCPData:(NSData *)data {
    __weak TCPTunnel *weakSelf = self;
    dispatch_async(socketQueue, ^{
        if (_isClosed)
            return;
        
        buffer_t *buf;
        
        if (_stage == STAGE_PARSE)
            buf = _buf;
        else
            buf = _remote->_buf;
        
        if (buf == NULL)    // TCPTunnelRemote has been closed
            return;
        
        memcpy(buf->data + buf->len, data.bytes, data.length);
        buf->len += data.length;
        
        if (_stage == STAGE_STREAM)
            [weakSelf handle_stage_stream];
        else if (_stage == STAGE_PARSE)
            [weakSelf handle_stage_parse:buf];
    });
}

- (void)closeTunnel {

    __weak TCPTunnel *weakSelf = self;
    dispatch_async(socketQueue, ^{
        if (weakSelf.isClosed)
            return;
        
        weakSelf.isClosed = YES;
        [weakSelf free];
        [weakSelf.delegate tcpTunnelDidClose:self];
        weakSelf.delegate = nil;
    });
}

@end

@interface TCPTunnelRemote() <GCDAsyncSocketDelegate>

@end

@implementation TCPTunnelRemote

- (instancetype)initWithHost:(NSString *)host port:(NSUInteger)port {
    self = [super init];
    if (self) {
        _host = host;
        _port = port;
        _sock = [[GCDAsyncSocket alloc] initWithDelegate:self delegateQueue:socketQueue];
        
        _buf = ss_malloc(sizeof(buffer_t));
        balloc(_buf, BUF_SIZE);
    }
    
    return self;
}

- (void)free {
    [_sock setDelegate:nil delegateQueue:NULL];
    _sock = nil;
    
    [_server closeTunnel];
    _server = nil;
    
    if (_buf) {
        bfree(_buf);
        _buf = nil;
    }
}

#pragma mark - Remote GCDAsynSocket Delegate

- (void)socket:(GCDAsyncSocket *)sock didConnectToHost:(NSString *)host port:(uint16_t)port {
    _isConnecting = NO;
    NSLog(@"Remote: connect to %@:%d", host, port);
    
    [sock readDataWithTimeout:timeout buffer:nil bufferOffset:0 maxLength:BUF_SIZE tag:0];
}

- (void)socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag {
    
    if (!_server || _server.delegate == nil)
        return;
    
    NSUInteger r = data.length;
    
    memcpy(_server->_buf->data, data.bytes, r);
    _server->_buf->len = r;
    
    if (!_direct) {
        int err = crypto->decrypt(_server->_buf, _server->_d_ctx, BUF_SIZE);
        if (err == CRYPTO_ERROR) {
            NSLog(@"invalid password or cipher");
            
            [_sock disconnect];
            return;
        }
        else if (err == CRYPTO_NEED_MORE) {
            // Wait for more
            [sock readDataWithTimeout:timeout buffer:nil bufferOffset:0 maxLength:BUF_SIZE tag:0];
            return;
        }
    }
    
    NSData *sendData = [NSData dataWithBytes:_server->_buf->data length:_server->_buf->len];
    [_server.delegate tcpTunnel:_server didReadData:sendData];
        
    _server->_buf->len = 0;
    _server->_buf->idx = 0;
    
    // Queue next read
    [sock readDataWithTimeout:timeout buffer:nil bufferOffset:0 maxLength:BUF_SIZE tag:0];
}

- (void)socket:(GCDAsyncSocket *)sock didWritePartialDataOfLength:(NSUInteger)partialLength tag:(long)tag {
    NSLog(@"Remote: %lu bytes partial data in STAGE %d", (unsigned long)partialLength, _server->_stage);
}

- (void)socket:(GCDAsyncSocket *)sock didWriteDataWithTag:(long)tag {
    
    switch (tag) {
        case TFO_SYN:
            NSLog(@"TFO_SYN");
            break;
    }
    
}

- (void)socketDidDisconnect:(GCDAsyncSocket *)sock withError:(NSError *)err {
    if (err)
        NSLog(@"Remote did disconnect with error: %@", err);
    else
        NSLog(@"Remote did disconnect");
    
    [self free];
}

@end
