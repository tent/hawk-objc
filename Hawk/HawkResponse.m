//
//  HawkResponse.m
//  Hawk
//
//  Created by Jesse Stuart on 8/8/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import "HawkResponse.h"

@implementation HawkResponse

+ (HawkResponse *)hawkResponseWithCredentials:(HawkCredentials *)credentials
{
    HawkResponse *response = [[HawkResponse alloc] init];
    response.credentials = credentials;

    return response;
}

+ (HawkResponse *)hawkResponseWithErrorReason:(HawkErrorReason)reason
{
    HawkResponse *response = [[HawkResponse alloc] init];
    response.error = [HawkError hawkErrorWithReason:reason];

    return response;
}

@end
