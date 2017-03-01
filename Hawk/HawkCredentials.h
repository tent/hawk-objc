//
//  HawkCredentials.h
//  Hawk
//
//  Created by Jesse Stuart on 8/7/13.
//  Copyright (c) 2013 Tent.is, LLC. All rights reserved.
//  Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.
//

#import <Foundation/Foundation.h>
#import "CryptoProxy.h"

@interface HawkCredentials : NSObject

/*
 http://stackoverflow.com/questions/9859719/objective-c-declared-property-attributes-nonatomic-copy-strong-weak
 */
@property (readonly, strong, nonatomic) NSString *keyId;
@property (readonly, strong, nonatomic) NSString *key;
@property (readonly, nonatomic) CryptoAlgorithm algorithm;

+ (instancetype)withKeyId:(NSString *)hawkId
                      key:(NSString *)key
                algorithm:(CryptoAlgorithm)algorithm;

/*
 @return A copy of the original credentials with the algorithm replaced
 */
- (instancetype)copyWithAlgorithm:(CryptoAlgorithm)algorithm;

@end
