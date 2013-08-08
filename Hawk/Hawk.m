//
//  Hawk.m
//  Hawk
//
//  Created by Jesse Stuart on 8/6/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import "Hawk.h"
#import "NSString+Parser.h"
#import "NSString+Base64.h"

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

+ (NSString *)mac:(HawkAuthAttributes *)attributes
{
    NSMutableData *normalizedString = [[NSMutableData alloc] init];

    if (!attributes.hawkType) {
        attributes.hawkType = @"header";
    }

    // header
    [normalizedString appendData:[[NSString stringWithFormat:@"hawk.1.%@\n", attributes.hawkType] dataUsingEncoding:NSUTF8StringEncoding]];

    // timestamp
    [normalizedString appendData:[[NSString stringWithFormat:@"%i\n", (int)[attributes.timestamp timeIntervalSince1970]] dataUsingEncoding:NSUTF8StringEncoding]];

    if (![attributes.hawkType isEqualToString:@"ts"]) {
        // nonce
        if (attributes.nonce) {
            [normalizedString appendData:[attributes.nonce dataUsingEncoding:NSUTF8StringEncoding]];
        }
        [normalizedString appendData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];

        // method
        [normalizedString appendData:[attributes.method dataUsingEncoding:NSUTF8StringEncoding]];
        [normalizedString appendData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];

        // request uri
        [normalizedString appendData:[attributes.requestUri dataUsingEncoding:NSUTF8StringEncoding]];
        [normalizedString appendData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];

        // host
        [normalizedString appendData:[attributes.host dataUsingEncoding:NSUTF8StringEncoding]];
        [normalizedString appendData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];

        // port
        [normalizedString appendData:[[NSString stringWithFormat:@"%i\n", (int)[attributes.port integerValue]] dataUsingEncoding:NSUTF8StringEncoding]];

        // hash
        if (attributes.payload) {
            [normalizedString appendData:[[self payloadHashWithAttributes:attributes] dataUsingEncoding:NSUTF8StringEncoding]];
        }
        [normalizedString appendData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];

        // ext
        if (attributes.ext) {
            [normalizedString appendData:[attributes.ext dataUsingEncoding:NSUTF8StringEncoding]];
        }
        [normalizedString appendData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];

        // app
        if (attributes.app) {
            if (!attributes.dig) {
                attributes.dig = @"";
            }

            [normalizedString appendData:[[NSString stringWithFormat:@"%@\n", attributes.app] dataUsingEncoding:NSUTF8StringEncoding]];
            [normalizedString appendData:[[NSString stringWithFormat:@"%@\n", attributes.dig] dataUsingEncoding:NSUTF8StringEncoding]];
        }
    }

    const char *key = [attributes.credentials.key cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char hmac[CC_SHA256_DIGEST_LENGTH];

    CCHmac(kCCHmacAlgSHA256, key, strlen(key), normalizedString.mutableBytes, (CC_LONG)normalizedString.length, hmac);

    NSData *output = [NSData dataWithBytes:hmac length:CC_SHA256_DIGEST_LENGTH];

    return [output base64EncodedString];
}

+ (NSString *)responseMac:(HawkAuthAttributes *)attributes
{
    attributes.hawkType = @"response";
    return [Hawk mac:attributes];
}

+ (NSString *)bewit:(HawkAuthAttributes *)attributes
{
    HawkAuthAttributes *authAttributes = [[HawkAuthAttributes alloc] init];
    authAttributes.hawkType = @"bewit";
    authAttributes.credentials = attributes.credentials;
    authAttributes.timestamp = attributes.timestamp;
    authAttributes.method = attributes.method;
    authAttributes.host = attributes.host;
    authAttributes.port = attributes.port;
    authAttributes.requestUri = attributes.requestUri;
    authAttributes.ext = attributes.ext;

    if (!authAttributes.ext) {
        authAttributes.ext = @"";
    }

    NSString *mac = [Hawk mac:authAttributes];

    NSString *normalizedString = [NSString stringWithFormat:@"%@\\%i\\%@\\%@", authAttributes.credentials.hawkId, (int)[authAttributes.timestamp timeIntervalSince1970], mac, authAttributes.ext];

    NSString *bewit = [[normalizedString base64EncodedString] stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"="]];

    return bewit;
}

+ (NSString *)timestampSkewMac:(HawkAuthAttributes *)attributes
{
    attributes.hawkType = @"ts";
    NSString *tsm = [Hawk mac:attributes];

    return tsm;
}

+ (NSString *)authorizationHeader:(HawkAuthAttributes *)attributes
{
    NSMutableData *header = [[NSMutableData alloc] init];

    [header appendData:[[NSString stringWithFormat:@"Authorization: Hawk id=\"%@\"", attributes.credentials.hawkId] dataUsingEncoding:NSUTF8StringEncoding]];

    [header appendData:[[NSString stringWithFormat:@", mac=\"%@\"", [self mac:attributes]] dataUsingEncoding:NSUTF8StringEncoding]];

    [header appendData:[[NSString stringWithFormat:@", ts=\"%i\"", (int)[attributes.timestamp timeIntervalSince1970]] dataUsingEncoding:NSUTF8StringEncoding]];

    [header appendData:[[NSString stringWithFormat:@", nonce=\"%@\"", attributes.nonce] dataUsingEncoding:NSUTF8StringEncoding]];

    if (attributes.payload) {
        [header appendData:[[NSString stringWithFormat:@", hash=\"%@\"", [self payloadHashWithAttributes:attributes]] dataUsingEncoding:NSUTF8StringEncoding]];
    }

    if (attributes.app) {
        [header appendData:[[NSString stringWithFormat:@", app=\"%@\"", attributes.app] dataUsingEncoding:NSUTF8StringEncoding]];
    }

    return [[NSString alloc] initWithData:header encoding:NSUTF8StringEncoding];
}

+ (NSString *)serverAuthorizationHeader:(HawkAuthAttributes *)attributes
{
    NSMutableData *header = [[NSMutableData alloc] initWithData:[[NSString stringWithFormat:@"Server-Authorization: Hawk mac=\"%@\"", [Hawk responseMac:attributes]] dataUsingEncoding:NSUTF8StringEncoding]];

    if (attributes.payload) {
        [header appendData:[[NSString stringWithFormat:@", hash=\"%@\"", [Hawk payloadHashWithAttributes:attributes]] dataUsingEncoding:NSUTF8StringEncoding]];
    }

    return [[NSString alloc] initWithData:header encoding:NSUTF8StringEncoding];
}

+ (NSString *)timestampSkewHeader:(HawkAuthAttributes *)attributes
{
    NSString *tsm = [Hawk timestampSkewMac:attributes];
    NSString *header = [NSString stringWithFormat:@"WWW-Authenticate: Hawk ts=\"%i\", tsm=\"%@\", error=\"timestamp skew too high\"", (int)[attributes.timestamp timeIntervalSince1970], tsm];

    return header;
}

+ (HawkResponse *)validateAuthorizationHeader:(NSString *)header hawkAuthAttributes:(HawkAuthAttributes *)hawkAuthAttributes credentialsLookup:(HawkCredentials *(^)(NSString *))credentialsLookup nonceLookup:(BOOL (^)(NSString *))nonceLookup
{
    NSUInteger *splitIndex = [header firstIndexOf:@","];
    NSString *hawkId = [[header substringToIndex:(int)splitIndex - 1] substringFromIndex:(int)[header firstIndexOf:@"id"] + 4];

    HawkCredentials *credentials = credentialsLookup(hawkId);

    if (!credentials) {
        return [HawkResponse hawkResponseWithErrorReason:HawkErrorUnknownId];
    }

    HawkAuthAttributes *authAttributes = [HawkAuthAttributes hawkAuthAttributesFromAuthorizationHeader:header];
    [authAttributes mergeHawkAuthAttributes:hawkAuthAttributes];
    authAttributes.credentials = credentials;

    if (authAttributes.payloadHash) {
        NSString *expectedPayloadHash = [Hawk payloadHashWithAttributes:authAttributes];
        if (![expectedPayloadHash isEqualToString:authAttributes.payloadHash]) {
            return [HawkResponse hawkResponseWithErrorReason:HawkErrorInvalidPayloadHash];
        }
    }

    NSString *expectedMac = [Hawk mac:authAttributes];

    if (![expectedMac isEqualToString:authAttributes.mac]) {
        return [HawkResponse hawkResponseWithErrorReason:HawkErrorInvalidMac];
    }

    return [HawkResponse hawkResponseWithCredentials:credentials];
}

+ (HawkResponse *)validateBewit:(NSString *)bewit hawkAuthAttributes:(HawkAuthAttributes *)hawkAuthAttributes serverTimestamp:(NSDate *)serverTimestamp credentialsLookup:(HawkCredentials *(^)(NSString *))credentialsLookup
{
    NSString *padding = [[[NSString alloc] init] stringByPaddingToLength:((4 - bewit.length) % 4) withString:@"=" startingAtIndex:0];

    NSString *normalizedString = [[bewit stringByAppendingString:padding] base64DecodedString];

    NSArray *parts = [normalizedString componentsSeparatedByString:@"\\"];

    if (parts.count != 4) {
        return [HawkResponse hawkResponseWithErrorReason:HawkErrorMalformedBewit];
    }

    NSString *hawkId = [parts objectAtIndex:0];
    HawkCredentials *credentials = credentialsLookup(hawkId);

    if (!credentials) {
        return [HawkResponse hawkResponseWithErrorReason:HawkErrorUnknownId];
    }

    HawkAuthAttributes *authAttributes = [[HawkAuthAttributes alloc] init];
    [authAttributes mergeHawkAuthAttributes:hawkAuthAttributes];
    authAttributes.credentials = credentials;
    authAttributes.timestamp = [[NSDate alloc] initWithTimeIntervalSince1970:[[[NSNumberFormatter alloc] numberFromString:[parts objectAtIndex:1]] doubleValue]];
    authAttributes.mac = [parts objectAtIndex:2];
    authAttributes.ext = [parts objectAtIndex:3];
    authAttributes.hawkType = @"bewit";

    if ([authAttributes.timestamp timeIntervalSince1970] > [serverTimestamp timeIntervalSince1970]) {
        return [HawkResponse hawkResponseWithErrorReason:HawkErrorBewitExpired];
    }

    NSString *expectedMac = [Hawk mac:authAttributes];

    if (![expectedMac isEqualToString:authAttributes.mac]) {
        return [HawkResponse hawkResponseWithErrorReason:HawkErrorInvalidMac];
    }

    return [HawkResponse hawkResponseWithCredentials:credentials];
}

+ (HawkResponse *)validateServerAuthorizationHeader:(NSString *)header hawkAuthAttributes:(HawkAuthAttributes *)hawkAuthAttributes
{
    HawkAuthAttributes *authAttributes = [HawkAuthAttributes hawkAuthAttributesFromAuthorizationHeader:header];
    [authAttributes mergeHawkAuthAttributes:hawkAuthAttributes];

    NSString *expectedMac = [Hawk responseMac:hawkAuthAttributes];

    if (authAttributes.payloadHash) {
        NSString *expectedPayloadHash = [Hawk payloadHashWithAttributes:hawkAuthAttributes];

        if (![expectedPayloadHash isEqualToString:authAttributes.payloadHash]) {
            return [HawkResponse hawkResponseWithErrorReason:HawkErrorInvalidPayloadHash];
        }
    }

    if (![expectedMac isEqualToString:authAttributes.mac]) {
        return [HawkResponse hawkResponseWithErrorReason:HawkErrorInvalidMac];
    }

    return [HawkResponse hawkResponseWithCredentials:authAttributes.credentials];
}

@end
