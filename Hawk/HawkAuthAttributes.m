//
//  HawkAuthAttributes.m
//  Hawk
//
//  Created by Jesse Stuart on 8/7/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import "HawkAuthAttributes.h"
#import "NSString+Parser.h"

@implementation HawkAuthAttributes

+ (HawkAuthAttributes *)hawkAuthAttributesFromAuthorizationHeader:(NSString *)header
{
    HawkAuthAttributes *attributes = [[HawkAuthAttributes alloc] init];

    NSArray *parts = [[header substringFromIndex:(int)[header firstIndexOf:@"id"]] componentsSeparatedByString:@", "];

    NSString *partKey;
    NSString *partValue;
    NSUInteger *splitIndex;
    for (NSString *part in parts) {

        splitIndex = [part firstIndexOf:@"="];

        partKey = [part substringToIndex:(int)splitIndex];

        partValue = [part substringFromIndex:(int)splitIndex + 2]; // remove key="
        partValue = [partValue substringToIndex:partValue.length - 1]; // remove trailing "

        if ([partKey isEqualToString:@"app"]) {
            attributes.app = partValue;
        } else if ([partKey isEqualToString:@"hash"]) {
            attributes.payloadHash = partValue;
        } else if ([partKey isEqualToString:@"nonce"]) {
            attributes.nonce = partValue;
        } else if ([partKey isEqualToString:@"ts"]) {
            attributes.timestamp = [[NSDate alloc] initWithTimeIntervalSince1970:[[[NSNumberFormatter alloc] numberFromString:partValue] doubleValue]];
        } else if ([partKey isEqualToString:@"mac"]) {
            attributes.mac = partValue;
        }
    }

    return attributes;
}

- (void)mergeHawkAuthAttributes:(HawkAuthAttributes *)otherAttributes
{
    if (otherAttributes.credentials) {
        self.credentials = otherAttributes.credentials;
    }

    if (otherAttributes.app) {
        self.app = otherAttributes.app;
    }

    if (otherAttributes.ext) {
        self.ext = otherAttributes.ext;
    }

    if (otherAttributes.nonce) {
        self.nonce = otherAttributes.nonce;
    }

    if (otherAttributes.timestamp) {
        self.timestamp = otherAttributes.timestamp;
    }

    if (otherAttributes.requestUri) {
        self.requestUri = otherAttributes.requestUri;
    }

    if (otherAttributes.method) {
        self.method = otherAttributes.method;
    }

    if (otherAttributes.contentType) {
        self.contentType = otherAttributes.contentType;
    }

    if (otherAttributes.host) {
        self.host = otherAttributes.host;
    }

    if (otherAttributes.port) {
        self.port = otherAttributes.port;
    }

    if (otherAttributes.payload) {
        self.payload = otherAttributes.payload;
    }
}

@end
