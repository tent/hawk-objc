//
//  HawkAuthAttributes.h
//  Hawk
//
//  Created by Jesse Stuart on 8/7/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "HawkCredentials.h"

@interface HawkAuthAttributes : NSObject

@property (nonatomic) HawkCredentials *credentials;
@property (copy) NSString *app;
@property (copy) NSString *dig;
@property (copy) NSString *ext;
@property (copy) NSString *nonce;
@property (copy) NSDate *timestamp;
@property (copy) NSString *contentType;
@property (copy) NSString *method;
@property (copy) NSString *requestUri;
@property (copy) NSString *host;
@property (copy) NSNumber *port;
@property (copy) NSData *payload;

@property (copy) NSString *hawkType;

@property (copy) NSString *payloadHash;
@property (copy) NSString *mac;

+ (HawkAuthAttributes *)hawkAuthAttributesFromAuthorizationHeader:(NSString *)header;

- (void)mergeHawkAuthAttributes:(HawkAuthAttributes *)otherAttributes;

@end
