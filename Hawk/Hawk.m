//
//  Hawk.m
//  Hawk
//
//  Created by Jesse Stuart on 8/6/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import "Hawk.h"

@implementation Hawk

+ (NSString *)payloadHashWithAttributes:(HawkAuthAttributes *)attributes

{
    NSMutableData *payloadNormalizedString = [[NSMutableData alloc] init];

    [payloadNormalizedString appendData:[@"hawk.1.payload\n" dataUsingEncoding:NSUTF8StringEncoding]];

    [payloadNormalizedString appendData:[attributes.contentType dataUsingEncoding:NSUTF8StringEncoding]];
    [payloadNormalizedString appendData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];

    [payloadNormalizedString appendData:attributes.payload];
    [payloadNormalizedString appendData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(payloadNormalizedString.mutableBytes, (CC_LONG)payloadNormalizedString.length, hash);

    NSData *output = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];

    return [output base64EncodedString];
}

@end
