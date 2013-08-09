//
//  CryptoProxy.m
//  Hawk
//
//  Created by Jesse Stuart on 8/9/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import "CryptoProxy.h"

@implementation CryptoProxy

+ (CryptoProxy *)cryptoProxyWithAlgorithm:(CryptoAlgorithm)algorithm
{
    CryptoProxy *cryptoProxy = [[CryptoProxy alloc] init];

    cryptoProxy.algorithm = algorithm;

    return cryptoProxy;
}

- (NSData *)digestFromData:(NSData *)input
{
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(input.bytes, (CC_LONG)input.length, hash);

    NSData *output = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];

    return output;
}

- (NSData *)hmacFromData:(NSData *)input withKey:(NSString *)key
{
    const char *cKey = [key cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char hmac[CC_SHA256_DIGEST_LENGTH];

    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), input.bytes, (CC_LONG)input.length, hmac);

    NSData *output = [NSData dataWithBytes:hmac length:CC_SHA256_DIGEST_LENGTH];

    return output;
}

@end
