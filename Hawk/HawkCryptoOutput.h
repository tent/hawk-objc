//
//  HawkCryptoOutput.h
//  Hawk
//
//  Created by Jesse Stuart on 8/9/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface HawkCryptoOutput : NSObject

@property (nonatomic) NSString *value;
@property (nonatomic) NSData *inputData;

+ (HawkCryptoOutput *)hawkCryptoOutputWithInputData:(NSData *)input outputValue:(NSString *)output;

@end
