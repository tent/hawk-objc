//
//  HawkCredentials.h
//  Hawk
//
//  Created by Jesse Stuart on 8/7/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CryptoProxy.h"

@interface HawkCredentials : NSObject

@property (copy) NSString *hawkId;
@property (copy) NSString *key;
@property (nonatomic) CryptoAlgorithm algorithm;

- (id)initWithHawkId:(NSString *)hawkId withKey:(NSString *)key withAlgorithm:(CryptoAlgorithm)algorithm;

@end
