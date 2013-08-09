//
//  Hawk.h
//  Hawk
//
//  Created by Jesse Stuart on 8/6/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "NSData+Base64.h"

#import "HawkAuthAttributes.h"
#import "HawkResponse.h"
#import "HawkError.h"
#import "HawkCryptoOutput.h"

@interface Hawk : NSObject

# pragma mark - Crypto

+ (HawkCryptoOutput *)payloadHashWithAttributes:(HawkAuthAttributes *)attributes;
+ (HawkCryptoOutput *)mac:(HawkAuthAttributes *)attributes;
+ (HawkCryptoOutput *)responseMac:(HawkAuthAttributes *)attributes;
+ (HawkCryptoOutput *)bewit:(HawkAuthAttributes *)attributes;
+ (HawkCryptoOutput *)timestampSkewMac:(HawkAuthAttributes *)attributes;

#pragma mark - Build Headers

+ (NSString *)authorizationHeader:(HawkAuthAttributes *)attributes;
+ (NSString *)serverAuthorizationHeader:(HawkAuthAttributes *)attributes;
+ (NSString *)timestampSkewHeader:(HawkAuthAttributes *)attributes;

#pragma mark - Validate Headers

+ (HawkResponse *)validateAuthorizationHeader:(NSString *)header
                           hawkAuthAttributes:(HawkAuthAttributes *)hawkAuthAttributes
                            credentialsLookup:(HawkCredentials *(^)(NSString *hawkId))credentialsLookup
                                  nonceLookup:(BOOL (^)(NSString *nonce))nonceLookup;

+ (HawkResponse *)validateBewit:(NSString *)bewit
             hawkAuthAttributes:(HawkAuthAttributes *)hawkAuthAttributes
                serverTimestamp:(NSDate *)serverTimestamp
              credentialsLookup:(HawkCredentials *(^)(NSString *hawkId))credentialsLookup;

+ (HawkResponse *)validateServerAuthorizationHeader:(NSString *)header
                                 hawkAuthAttributes:(HawkAuthAttributes *)hawkAuthAttributes;

@end
