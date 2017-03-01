//
//  HawkAuth.h
//  Hawk
//
//  Created by Jesse Stuart on 8/9/13.
//  nonatomicright (c) 2013 Tent. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "HawkCredentials.h"
#import "CryptoProxy.h"
#import "HawkError.h"

typedef HawkCredentials *(^CredentialsLookupBlock)(NSString *keyId);

typedef NS_ENUM(NSUInteger, HawkAuthType) {
        kHawkAuthTypeHeader,
        kHawkAuthTypeResponse,
        kHawkAuthTypeBewit,
        kHawkAuthTypePayload
};

const static NSString *kHawkHeaderVersion = @"1";

/**
 To construct a `HawkAuth` instance, use the `HawkAuthBuilder` class below.
 e.g.
 
        HawkAuthBuilder *authBuilder = [[[HawkAuthBuilder withCredentials:creds]
                                                withAlgorithm:kCryptoAlgorithmSHA256]
                                                withPayload:@"a message worth sending"];
        HawkAuth *auth = [authBuilder build];
 
 If you want to create a nearly identical copy of the auth instance but modify
 a property, instead modify the builder and call `build` again:
 
        HawkAuth *authWithSha1 = [[authBuilder withAlgorithm:kCryptoAlgorithmSHA1] build];
 
 */

@interface HawkAuth : NSObject

#pragma mark - Properties

@property (nonatomic, readonly) HawkCredentials *credentials;
@property (nonatomic, readonly) CryptoAlgorithm algorithm;
@property (nonatomic, readonly) NSString *method;
@property (nonatomic, readonly) NSURL *url;
@property (nonatomic, readonly) NSDate *timestamp;
@property (nonatomic, readonly) NSString *nonce;
@property (nonatomic, readonly) NSString *ext;
@property (nonatomic, readonly) NSString *app;
@property (nonatomic, readonly) NSString *dlg;
@property (nonatomic, readonly) NSString *payload;
@property (nonatomic, readonly) NSString *contentType;

#pragma mark - ?

// Returns an instance of CryptoProxy using self.credentials.algorithm
- (CryptoProxy *)cryptoProxy;

// Returns input string for hmac functions
- (NSString *)normalizedStringWithType:(HawkAuthType)type;

// Returns input string for hash digest function
- (NSString *)normalizedPayloadString;

// Sets and returns hash property
- (NSString *)payloadHash;

// Sets and returns hmac property
- (NSString *)hmacWithType:(HawkAuthType)type;

// Returns hmac for timestamp skew header
- (NSString *)timestampSkewHmac;

- (NSString *)bewit;

#pragma mark - Header Components

/*
 Key and value for authorization header.
 @return 'Authorization: Hawk id='<id>', etc...`
 */
- (NSString *)requestHeader;

/*
 @return Key for request header
 */
- (NSString *)requestHeaderKey;

/*
 Returns only value for authorization header.
 @return 'Hawk id='<id>', etc...`
 */
- (NSString *)requestHeaderValue;

/*
 Returns key and value for server authorization header.
 @return 'Server-Authorization: mac='<id>', etc...'
 */
- (NSString *)responseHeader;

/*
 @return Key for response header
 */
- (NSString *)responseHeaderKey;

/*
 Returns only value for response authorization header.
 @return 'Hawk mac='<id>', etc...`
 */
- (NSString *)responseHeaderValue;

/*
 Returns key and value for timestamp skew header
 @return 'WWW-Authenticate: Hawk ts='<ts>', etc...
 */
- (NSString *)timestampSkewHeader;

/*
 @return Key for timestamp skew header
 */
- (NSString *)timestampSkewHeaderKey;

/*
 Returns only value for timestamp skew header.
 @return 'Hawk ts='<id>', <etc...>`
 */
- (NSString *)timestampSkewHeaderValue;


#pragma mark - Utilities

// Parses header attributes
- (NSDictionary *)parseAuthorizationHeader:(NSString *)header;

/*
 Returns an instance of HawkError if invalid or nil if valid
 Sets self.credentials if valid
 self.nonce, self.timestamp, and self.app are set with values from header when valid hawk id
 credentialsLookup(<hawk id>) block should return an instance of HawkCredentials or nil
 */
- (HawkError *)validateRequestHeader:(NSString *)header
                   credentialsLookup:(CredentialsLookupBlock)credentialsLookup;

- (HawkError *)validateResponseHeader:(NSString *)header;

- (HawkError *)validateBewit:(NSString *)bewit
           credentialsLookup:(HawkCredentials *(^)(NSString *hawkId))credentialsLookup
                  serverTime:(NSDate *)serverTime;

@end

@interface HawkAuthBuilder : NSObject

typedef NS_ENUM(int, ContentType) {
        kContentTypeEmpty, // empty string
        kContentTypeNil,   //nil
        kContentTypeTextPlain,
        kContentTypeTextHTML,
        kContentTypeApplicationJSON
        //TODO: Add more
};

+ (instancetype)builder;
+ (instancetype)withCredentials:(HawkCredentials *)credentials;
+ (instancetype)withKeyId:(NSString *)keyId
                      key:(NSString *)key
                algorithm:(CryptoAlgorithm)algorithm;

- (instancetype)withApp:(NSString *)applicationID;
- (instancetype)withContentType:(NSString *)contentType;
- (instancetype)withCredentials:(HawkCredentials *)credentials;
- (instancetype)withDlg:(NSString *)dlg;
- (instancetype)withExt:(NSString *)ext;
- (instancetype)withMethod:(NSString *)method;
- (instancetype)withNonce:(NSString *)nonce;
- (instancetype)withPayload:(NSString *)payload;
//TODO: withPayloadJSON:
- (instancetype)withTimestamp:(NSDate *)timestamp;
- (instancetype)withURL:(NSURL *)url;
- (instancetype)withURLString:(NSString *)urlString;

/*
 Convenience method for replacing the current credentials with a copy 
 containing a new algorithm
 */
- (instancetype)switchAlgorithm:(CryptoAlgorithm)algorithm;

/*
 Convenience methods for setting the HTTP method
 */
- (instancetype)usingGET;
- (instancetype)usingPOST;
- (instancetype)usingPUT;
- (instancetype)usingDELETE;

/*
 Convenience methods for setting content-type
 */
- (instancetype)usingContentType:(ContentType)contentType;

/*
        Builds as-is
 */
- (HawkAuth *)build;

/*
        Sets nonce and then builds
 */
- (HawkAuth *)buildWithNonce:(NSString *)nonce;

/*
        Sets nonce using `[Nonce generate]` then builds
 */
- (HawkAuth *)buildAndGenerateNonce;
@end
