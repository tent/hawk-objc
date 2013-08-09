//
//  HawkCryptoOutput.m
//  Hawk
//
//  Created by Jesse Stuart on 8/9/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import "HawkCryptoOutput.h"

@implementation HawkCryptoOutput

+ (HawkCryptoOutput *)hawkCryptoOutputWithInputData:(NSData *)input outputValue:(NSString *)output
{
    HawkCryptoOutput *hawkCryptoOutput = [[HawkCryptoOutput alloc] init];

    hawkCryptoOutput.inputData = input;
    hawkCryptoOutput.value = output;

    return hawkCryptoOutput;
}

@end
