//
//  HawkResponse.h
//  Hawk
//
//  Created by Jesse Stuart on 8/8/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "HawkCredentials.h"
#import "HawkError.h"
#import "HawkCryptoOutput.h"

@interface HawkResponse : NSObject

@property (nonatomic) HawkCredentials *credentials;
@property (nonatomic) HawkError *error;

+ (HawkResponse *)hawkResponseWithCredentials:(HawkCredentials *)credentials;
+ (HawkResponse *)hawkResponseWithErrorReason:(HawkErrorReason)reason;
+ (HawkResponse *)hawkResponseWithErrorReason:(HawkErrorReason)reason inputData:(NSData *)inputData;

@end
