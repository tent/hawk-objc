//
//  HawkCredentials.m
//  Hawk
//
//  Created by Jesse Stuart on 8/7/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import "HawkCredentials.h"

@implementation HawkCredentials

- (id)initWithHawkId:(NSString *)hawkId withKey:(NSString *)key withAlgorithm:(NSString *)algorithm
{
    self = [super init];

    self.hawkId = hawkId;
    self.key = key;
    self.algorithm = algorithm;

    return self;
}

@end
