//
//  CryptoProxy.h
//  Hawk
//
//  Created by Jesse Stuart on 8/9/13.
//  Copyright (c) 2013 Tent.is, LLC. All rights reserved.
//  Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, CryptoAlgorithm) {
    kCryptoAlgorithmSHA1,
    kCryptoAlgorithmSHA224,
    kCryptoAlgorithmSHA256,
    kCryptoAlgorithmSHA384,
    kCryptoAlgorithmSHA512
};

@interface CryptoProxy : NSObject

@property (nonatomic) CryptoAlgorithm algorithm;

+ (NSString *)algorithmToString:(CryptoAlgorithm)algorithm;

+ (CryptoProxy *)cryptoProxyWithAlgorithm:(CryptoAlgorithm)algorithm;

#pragma mark - Creating Digests
- (NSData *)digestFromData:(NSData *)input;
- (NSString *)digestFromString:(NSString *)input;

#pragma mark - Creating Hmacs
- (NSData *)hmacFromData:(NSData *)input withKey:(NSString *)key;
- (NSString *)hmacFromString:(NSString *)input withKey:(NSString *)key;

#pragma mark - Digest Convenience Methods

+ (NSData *)sha1DigestFromData:(NSData *)input;
+ (NSData *)sha224DigestFromData:(NSData *)input;
+ (NSData *)sha256DigestFromData:(NSData *)input;
+ (NSData *)sha384DigestFromData:(NSData *)input;
+ (NSData *)sha512DigestFromData:(NSData *)input;

#pragma mark - Hmac Convenience Methods

+ (NSData *)sha1HmacFromData:(NSData *)input withKey:(NSString *)key;
+ (NSData *)sha224HmacFromData:(NSData *)input withKey:(NSString *)key;
+ (NSData *)sha256HmacFromData:(NSData *)input withKey:(NSString *)key;
+ (NSData *)sha384HmacFromData:(NSData *)input withKey:(NSString *)key;
+ (NSData *)sha512HmacFromData:(NSData *)input withKey:(NSString *)key;

@end
