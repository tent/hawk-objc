//
//  HawkError.h
//  Hawk
//
//  Created by Jesse Stuart on 8/8/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, HawkErrorReason) {
    HawkErrorReply,
    HawkErrorInvalidPayloadHash,
    HawkErrorInvalidMac,
    HawkErrorBewitExpired,
    HawkErrorTimestampSkew,
    HawkErrorInvalidBewitMethod,
    HawkErrorUnknownId
};

@interface HawkError : NSObject

@property (nonatomic) HawkErrorReason errorReason;
@property (copy) NSString *normalizedString;

+ (HawkError *)hawkErrorWithReason:(HawkErrorReason)reason;
+ (HawkError *)hawkErrorWithReason:(HawkErrorReason)reason
                  normalizedString:(NSString *)normalizedString;

+ (NSString *)messageForReason:(HawkErrorReason)reason;

@end
