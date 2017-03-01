//
//  HawkCredentials.m
//  Hawk
//
//  Created by Jesse Stuart on 8/7/13.
//  Copyright (c) 2013 Tent.is, LLC. All rights reserved.
//  Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.
//

#import "HawkCredentials.h"

@implementation HawkCredentials

- (id)initWithKeyId:(NSString *)keyId
                 key:(NSString *)key
           algorithm:(CryptoAlgorithm)algorithm {
        if (self = [super init]) {
                _algorithm = algorithm;
                _keyId = keyId;
                _key = key;
        }
        return self;
}

+ (instancetype)withKeyId:(NSString *)keyId
                   key:(NSString *)key
                 algorithm:(CryptoAlgorithm)algorithm {
        return [[self alloc] initWithKeyId:keyId
                                       key:key
                                 algorithm:algorithm];
}

- (instancetype)copyWithAlgorithm:(CryptoAlgorithm)algorithm {
        return [HawkCredentials withKeyId:_keyId
                                      key:_key
                                algorithm:algorithm];
}

@end
