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

@interface Hawk : NSObject

+ (NSString *)payloadHashWithAttributes:(HawkAuthAttributes *)attributes;
+ (NSString *)mac:(HawkAuthAttributes *)attributes;
+ (NSString *)responseMac:(HawkAuthAttributes *)attributes;
+ (NSString *)bewit:(HawkAuthAttributes *)attributes;
+ (NSString *)timestampSkewMac:(HawkAuthAttributes *)attributes;
+ (NSString *)authorizationHeader:(HawkAuthAttributes *)attributes;
+ (NSString *)serverAuthorizationHeader:(HawkAuthAttributes *)attributes;
+ (NSString *)timestampSkewHeader:(HawkAuthAttributes *)attributes;
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
