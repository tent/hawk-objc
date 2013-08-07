//
//  HawkCredentials.h
//  Hawk
//
//  Created by Jesse Stuart on 8/7/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface HawkCredentials : NSObject

@property (copy) NSString *hawkId;
@property (copy) NSString *key;
@property (copy) NSString *algorithm;

- (id)initWithHawkId:(NSString *)hawkId withKey:(NSString *)key withAlgorithm:(NSString *)algorithm;

@end
