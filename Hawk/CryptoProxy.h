//
//  CryptoProxy.h
//  Hawk
//
//  Created by Jesse Stuart on 8/9/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>

typedef NS_ENUM(NSUInteger, CryptoAlgorithm) {
    CryptoAlgorithmSHA1,
    CryptoAlgorithmSHA224,
    CryptoAlgorithmSHA256,
    CryptoAlgorithmSHA384,
    CryptoAlgorithmSHA512
};

@interface CryptoProxy : NSObject

@property (nonatomic) CryptoAlgorithm algorithm;

+ (CryptoProxy *)cryptoProxyWithAlgorithm:(CryptoAlgorithm)algorithm;

- (NSData *)digestFromData:(NSData *)input;

- (NSData *)hmacFromData:(NSData *)input withKey:(NSString *)key;

@end
