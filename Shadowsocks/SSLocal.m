/*
 *  SSLocal.m
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

#import "SSLocal.h"

#include <arpa/inet.h>

#include "shadowsocks-core/utils.h"
#include "socks5.h"
#include "http.h"
#include "tls.h"

#include <mbedtls/cipher.h>
#include <libsodium/sodium.h>

#import <CocoaAsyncSocket/GCDAsyncSocket.h>

#define BUF_SIZE 2048

#define MAX_CONNECT_TIMEOUT 10

// Write tags
#define FAKE_REPLY 1
#define STREAM_WRITE 2
#define TFO_SYN 3

static dispatch_queue_t socketQueue;
static NSMutableSet *connections;
static crypto_t *crypto;

// Profile
static NSString *remoteHost;
static uint16_t remotePort;
static BOOL fastOpen;
static NSTimeInterval timeout;

int verbose;


@interface Server () <GCDAsyncSocketDelegate>

@end

@implementation Server

- (instancetype)initWithSock:(GCDAsyncSocket *)sock {
    if (self = [super init]) {
        _sock = sock;
        _stage = STAGE_INIT;
        
        _buf = ss_malloc(sizeof(buffer_t));
        _abuf = ss_malloc(sizeof(buffer_t));
        balloc(_buf, BUF_SIZE);
        balloc(_abuf, BUF_SIZE);
        
        _e_ctx = malloc(sizeof(cipher_ctx_t));
        _d_ctx = malloc(sizeof(cipher_ctx_t));
        crypto->ctx_init(crypto->cipher, _e_ctx, 1);
        crypto->ctx_init(crypto->cipher, _d_ctx, 0);
        
        [sock setDelegate:self];
    }

    return self;
}

- (void)new_remote{
    _remote = [[Remote alloc] initWithHost:remoteHost port:remotePort];
    _remote->_server = self;
}

- (void)handle_stage_stream {

        // insert shadowsocks header
        if (!_remote->_direct) {
            
            int err = crypto->encrypt(_remote->_buf, _e_ctx, BUF_SIZE);
            
            if (err) {
                NSLog(@"invalid password or cipher");
                [_sock disconnect];
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
                    [_sock disconnect];
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
                    [_sock disconnect];
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
        
        // all processed
}

- (void)handle_stage_init:(buffer_t *)buf {
    if (buf->len < 3)
        return;
    int method_len = (buf->data[1] & 0xff) + 2;
    if (buf->len < method_len) {
        return;
    }
    struct method_select_response response;
    response.ver    = SVERSION;
    response.method = 0;
    char *send_buf = (char *)&response;
    NSData *sendData = [NSData dataWithBytes:send_buf length:sizeof(response)];
    [_sock writeData:sendData withTimeout:-1 tag:0];
    _stage = STAGE_HANDSHAKE;
    
    // what is this?!
    if (buf->data[0] == 0x05 && method_len < (int)(buf->len)) {
        memmove(buf->data, buf->data + method_len , buf->len - method_len);
        buf->len -= method_len;
        // continue;
        [self handle_stage_handshake_parse:buf];
    }
    
    buf->len = 0;   // do clear server buffer here
    return;

}

- (void)handle_stage_handshake_parse:(buffer_t *)buf {
    struct socks5_request *request = (struct socks5_request *)buf->data;
    size_t request_len = sizeof(struct socks5_request);
    struct sockaddr_in sock_addr;
    memset(&sock_addr, 0, sizeof(sock_addr));
    
    if (buf->len < request_len) {
        return;
    }
    
    int udp_assc = 0;
    
    if (request->cmd == 3) {
        udp_assc = 1;
        socklen_t addr_len = sizeof(sock_addr);
        getsockname(_sock.socketFD, (struct sockaddr *)&sock_addr,
                    &addr_len);
        if (verbose)
            NSLog(@"udp assc request accepted");
        
    } else if (request->cmd != 1) {
        NSLog(@"unsupported cmd: %d", request->cmd);
        struct socks5_response response;
        response.ver  = SVERSION;
        response.rep  = CMD_NOT_SUPPORTED;
        response.rsv  = 0;
        response.atyp = 1;
        char *send_buf = (char *)&response;
        NSData *sendData = [NSData dataWithBytes:send_buf length:4];
        [_sock writeData:sendData withTimeout:-1 tag:0];
        
        [_sock disconnectAfterWriting];
        return;
    }
    
    // Fake reply
    if (_stage == STAGE_HANDSHAKE) {
        struct socks5_response response;
        response.ver  = SVERSION;
        response.rep  = 0;
        response.rsv  = 0;
        response.atyp = 1;
        
        buffer_t resp_to_send;
        buffer_t *resp_buf = &resp_to_send;
        balloc(resp_buf, BUF_SIZE);
        
        memcpy(resp_buf->data, &response, sizeof(struct socks5_response));
        memcpy(resp_buf->data + sizeof(struct socks5_response),
               &sock_addr.sin_addr, sizeof(sock_addr.sin_addr));
        memcpy(resp_buf->data + sizeof(struct socks5_response) +
               sizeof(sock_addr.sin_addr),
               &sock_addr.sin_port, sizeof(sock_addr.sin_port));
        
        int reply_size = sizeof(struct socks5_response) +
        sizeof(sock_addr.sin_addr) + sizeof(sock_addr.sin_port);
        
        NSData *sendData = [NSData dataWithBytes:resp_buf->data length:reply_size];
        [_sock writeData:sendData withTimeout:-1 tag:FAKE_REPLY];
        
        bfree(resp_buf);
        
        if (udp_assc) {
            [_sock disconnect];
            return;
        }
    }
    
    char host[257], ip[INET6_ADDRSTRLEN], port[16];
    
    buffer_t *abuf = _abuf;
    abuf->idx = 0;
    abuf->len = 0;
    
    abuf->data[abuf->len++] = request->atyp;
    int atyp = request->atyp;
    
    // get remote addr and port
    if (atyp == 1) {
        // IP V4
        size_t in_addr_len = sizeof(struct in_addr);
        if (buf->len < request_len + in_addr_len + 2) {
            return;
        }
        memcpy(abuf->data + abuf->len, buf->data + 4, in_addr_len + 2);
        abuf->len += in_addr_len + 2;
        
        //                if (acl || verbose) {
        if (verbose) {
            uint16_t p = ntohs(*(uint16_t *)(buf->data + 4 + in_addr_len));
            inet_ntop(AF_INET, (const void *)(buf->data + 4), ip, INET_ADDRSTRLEN);
            sprintf(port, "%d", p);
        }
    } else if (atyp == 3) {
        // Domain name
        uint8_t name_len = *(uint8_t *)(buf->data + 4);
        if (buf->len < request_len + name_len + 2) {
            return;
        }
        abuf->data[abuf->len++] = name_len;
        memcpy(abuf->data + abuf->len, buf->data + 4 + 1, name_len + 2);
        abuf->len += name_len + 2;
        
        //                if (acl || verbose) {
        if (verbose) {
            uint16_t p =
            ntohs(*(uint16_t *)(buf->data + 4 + 1 + name_len));
            memcpy(host, buf->data + 4 + 1, name_len);
            host[name_len] = '\0';
            sprintf(port, "%d", p);
        }
    } else if (atyp == 4) {
        // IP V6
        size_t in6_addr_len = sizeof(struct in6_addr);
        if (buf->len < request_len + in6_addr_len + 2) {
            return;
        }
        memcpy(abuf->data + abuf->len, buf->data + 4, in6_addr_len + 2);
        abuf->len += in6_addr_len + 2;
        
        //                if (acl || verbose) {
        if (verbose) {
            uint16_t p = ntohs(*(uint16_t *)(buf->data + 4 + in6_addr_len));
            inet_ntop(AF_INET6, (const void *)(buf->data + 4), ip, INET6_ADDRSTRLEN);
            sprintf(port, "%d", p);
        }
    } else {
        NSLog(@"unsupported addrtype: %d", request->atyp);
        [_sock disconnect];
        return;
    }
    
    size_t abuf_len  = abuf->len;
    int sni_detected = 0;
    
    if (atyp == 1 || atyp == 4) {
        char *hostname = NULL;
        uint16_t p = ntohs(*(uint16_t *)(abuf->data + abuf->len - 2));
        int ret    = 0;
        if (p == http_default_port)
            ret = parse_http_header(buf->data + 3 + abuf->len, buf->len - 3 - abuf->len, &hostname);
        else if (p == tls_default_port)
            ret = parse_tls_header(buf->data + 3 + abuf->len, buf->len - 3 - abuf->len, &hostname);
        if (ret == -1 && buf->len < BUF_SIZE) {
            _stage = STAGE_PARSE;
            return;     // need read more
        } else if (ret > 0) {
            sni_detected = 1;
            
            // Reconstruct address buffer
            abuf->len               = 0;
            abuf->data[abuf->len++] = 3;
            abuf->data[abuf->len++] = ret;
            memcpy(abuf->data + abuf->len, hostname, ret);
            abuf->len += ret;
            p          = htons(p);
            memcpy(abuf->data + abuf->len, &p, 2);
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
    
    buf->len -= (3 + abuf_len);
    if (buf->len > 0) {
        memmove(buf->data, buf->data + 3 + abuf_len, buf->len);
    }
    
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
    //                        remote = create_remote(server->listener, (struct sockaddr *)&storage);
    //                        if (remote != NULL)
    //                            remote->direct = 1;
    //                    }
    //                }
    //            }
    
    // Not match ACL
    if (!_remote)
        [self new_remote];
    
    
    if (!_remote->_direct) {
        int err = crypto->encrypt(abuf, _e_ctx, BUF_SIZE);
        if (err) {
            NSLog(@"invalid password or cipher");
            [_sock disconnect];
            return;
        }
    }
    
    if (buf->len > 0) {
        memcpy(_remote->_buf->data, buf->data, buf->len);
        _remote->_buf->len = buf->len;
    }
    
    [self handle_stage_stream];
    
}

// Can be called mannually or automatically in socketDidDisconnect:
- (void)free {
    [_sock setDelegate:nil delegateQueue:NULL];
    if ([_sock isConnected])
        [_sock disconnect];
    _sock = nil;
    
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

#pragma mark - Server GCDAsynSocket Delegate

- (void)socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag
{
    if (sock.isDisconnected)
        return;
    
    buffer_t *buf;
    
    if (!_remote)
        buf = _buf;
    else            // not null means will be STAGE_STREAM
        buf = _remote->_buf;
    
    memcpy(buf->data + buf->len, data.bytes, data.length);
    buf->len += data.length;
    
    if (_stage == STAGE_STREAM)
        [self handle_stage_stream];
    else if (_stage == STAGE_INIT)
        [self handle_stage_init:buf];
    else if (_stage == STAGE_HANDSHAKE || _stage == STAGE_PARSE)
        [self handle_stage_handshake_parse:buf];
    
    // Queue next read
    [sock readDataWithTimeout:-1 buffer:nil bufferOffset:0 maxLength:BUF_SIZE tag:0];
}

- (void)socket:(GCDAsyncSocket *)sock didWritePartialDataOfLength:(NSUInteger)partialLength tag:(long)tag {
    
    switch (tag) {
        case FAKE_REPLY:
            NSLog(@"Failed to send fake reply");
            [sock disconnect];
            break;
        case STREAM_WRITE:
#warning how to deal with pratial write?
//            _remote.buf->len -= partialLength;
//            _remote.buf->idx  = partialLength;

            break;

    }
}

- (void)socket:(GCDAsyncSocket *)sock didWriteDataWithTag:(long)tag {
    
}

- (void)socketDidDisconnect:(GCDAsyncSocket *)sock withError:(NSError *)err {
    if (err)
        NSLog(@"Server did disconnect with error: %@", err);
    else
        NSLog(@"Server did disconnect");
    
    [connections removeObject:self];
    [self free];
}

@end

@interface Remote() <GCDAsyncSocketDelegate>

@end

@implementation Remote

- (instancetype)initWithHost:(NSString *)host port:(NSUInteger)port {
    self = [super init];
    if (self) {
        _host = remoteHost;
        _port = remotePort;
        _sock = [[GCDAsyncSocket alloc] initWithDelegate:self delegateQueue:socketQueue];
        //    if (!_remote) {
        //        NSLog(@"invalid remote addr");
        //        //                close_and_free_server(EV_A_ server);
        //        return;
        //    }
        
        
        _buf = ss_malloc(sizeof(buffer_t));
        balloc(_buf, BUF_SIZE);

    }

    return self;
}

- (void)free {
    [_sock setDelegate:nil delegateQueue:NULL];
    _sock = nil;
    
    // Give it a chance to relay data to client
    [_server->_sock disconnectAfterWriting];
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

    if (!_server || _server->_sock == nil)
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
    [_server->_sock writeData:sendData withTimeout:10 tag:99];
    
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

@interface SSLocal() <GCDAsyncSocketDelegate>
{
    GCDAsyncSocket *listenSocket;
    
    BOOL isRunning;
}
@end

@implementation SSLocal

- (id)init
{
    if((self = [super init]))
    {
        // Setup our logging framework.
//        [DDLog addLogger:[DDTTYLogger sharedInstance]];

        socketQueue = dispatch_queue_create("socketQueue", NULL);
        
        listenSocket = [[GCDAsyncSocket alloc] initWithDelegate:self delegateQueue:socketQueue];
        
        if (!connections)
            connections = [[NSMutableSet alloc] initWithCapacity:1];
        
        isRunning = NO;
    }
    return self;
}

- (void)createServerWithSocket:(GCDAsyncSocket *)sock {
    
    Server *server = [[Server alloc] initWithSock:sock];
    
    @synchronized(connections)
    {
        [connections addObject:server];
    }
    
    [sock readDataWithTimeout:-1 buffer:nil bufferOffset:0 maxLength:BUF_SIZE tag:0];
}

- (BOOL)startSSLocalServerWithProfile:(SSProfile *)profile {
    
    if (!profile)
        return NO;
    
    if (isRunning)
        [self stopSSLocalServer];
        
    remoteHost = profile.remoteHost;
    remotePort = profile.remotePort;
    const char *method = [profile.method cStringUsingEncoding:NSUTF8StringEncoding];
    const char *password = [profile.password cStringUsingEncoding:NSUTF8StringEncoding];
    
    timeout = profile.timeout;
    fastOpen = profile.isFastOpen;
    verbose = profile.verbose;
    
    // Setup keys
    NSLog(@"Initializing ciphers... %s", method);
    crypto = crypto_init(password, NULL, method);
    if (crypto == NULL)
        NSLog(@"Failed to init ciphers");
    
    NSError *error = nil;
    if(![listenSocket acceptOnPort:profile.localPort error:&error])
    {
        NSLog(@"Could not bind: %@", error);
        return NO;
    }
    NSLog(@"Listening on %d", profile.localPort);

    isRunning = YES;
    
    return YES;
}

- (void)stopSSLocalServer {
    [listenSocket disconnect];

    for (Server *server in connections) {
        [server free];
    }
    [connections removeAllObjects];
    connections = nil;
    
    isRunning = NO;
    NSLog(@"Stopped SSLocal Server");
}

#pragma mark GCDAsynSocket Delegate

- (void)socket:(GCDAsyncSocket *)sock didAcceptNewSocket:(GCDAsyncSocket *)newSocket
{    
    NSString *host = [newSocket connectedHost];
    UInt16 port = [newSocket connectedPort];
    
    NSLog(@"Accepted client %@:%hu", host, port);

    [self createServerWithSocket:newSocket];
}

@end
