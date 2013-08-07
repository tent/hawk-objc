//
//  Hawk.h
//  Hawk
//
//  Created by Jesse Stuart on 8/6/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>

#import "NSData+Base64.h"

#import "HawkAuthAttributes.h"

@interface Hawk : NSObject

+ (NSString *)payloadHashWithAttributes:(HawkAuthAttributes *)attributes;

@end
