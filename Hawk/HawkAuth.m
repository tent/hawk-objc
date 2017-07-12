//
//  HawkAuth.m
//  Hawk
//
//  Created by Jesse Stuart on 8/9/13.
//  Copyright (c) 2013 Tent.is, LLC. All rights reserved.
//  Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.
//

#import "Nonce.h"
#import "HawkAuth.h"
#import "NSString+Base64.h"

@interface HawkAuth()
@property (nonatomic, strong) NSString *app;
@property (nonatomic, strong) NSString *contentType;
@property (nonatomic, strong) HawkCredentials *credentials;
@property (nonatomic, strong) NSString *dlg;
@property (nonatomic, strong) NSString *ext;
@property (nonatomic, strong) NSString *host;
@property (nonatomic, strong) NSString *method;
@property (nonatomic, strong) NSString *nonce;
@property (nonatomic, strong) NSString *payload;
@property (nonatomic, strong) NSNumber *port;
@property (nonatomic, strong) NSString *resourcePath;
@property (nonatomic, strong) NSDate *timestamp;
@end

@implementation HawkAuth

- (CryptoProxy *)cryptoProxy {
        return [CryptoProxy cryptoProxyWithAlgorithm:self.credentials.algorithm];
}

- (NSString *)hawkAuthTypeToString:(HawkAuthType)type {
        switch (type) {
                case kHawkAuthTypeHeader:
                        return @"header";
                case kHawkAuthTypeResponse:
                        return @"response";
                case kHawkAuthTypeBewit:
                        return @"bewit";
                default:
                        NSAssert(NO, @"Unrecognized HawkAuthType: %@", @(type));
                        return nil;
        }
}

- (NSMutableString *)prefixForType:(NSString *)prefixType {
        return [NSMutableString stringWithFormat:@"hawk.%@.%@\n",
                kHawkHeaderVersion,
                prefixType];
}

- (NSString *)normalizedStringWithType:(HawkAuthType)type {
        NSMutableString *normalizedString = [self prefixForType:[self hawkAuthTypeToString:type]];
        
        [normalizedString appendFormat:@"%.0f\n", [self.timestamp timeIntervalSince1970]];
        [normalizedString appendFormat:@"%@\n", (self.nonce ?: @"")];
        [normalizedString appendFormat:@"%@\n", self.method];
        [normalizedString appendFormat:@"%@\n", self.resourcePath];
        [normalizedString appendFormat:@"%@\n", self.host];
        [normalizedString appendFormat:@"%@\n", self.port];
        [normalizedString appendFormat:@"%@\n", ([self payloadHash] ?: @"")];
        [normalizedString appendFormat:@"%@\n", (self.ext ?: @"")];
        
        if (self.app) {
                [normalizedString appendFormat:@"%@\n", (self.app ?: @"")];
                [normalizedString appendFormat:@"%@\n", (self.dlg ?: @"")];
        }
        
        return normalizedString;
}

- (NSString *)normalizedPayloadString {
        NSMutableString *normalizedString = [self prefixForType:@"payload"];
        
        NSArray *contentTypeSplit = [self.contentType componentsSeparatedByString:@";"];
        
        NSString *contentType = [[contentTypeSplit firstObject] // bounds-safe, defaults to nil
                                 stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        
        [normalizedString appendFormat:@"%@\n", (contentType ?: @"")];
        [normalizedString appendFormat:@"%@\n", (self.payload ?: @"")];
        
        return normalizedString;
}

- (NSString *)payloadHash {
        return self.payload ? [self.cryptoProxy digestFromString:[self normalizedPayloadString]]
        : nil;
}

- (NSString *)hmacWithType:(HawkAuthType)type {
        return [self.cryptoProxy hmacFromString:[self normalizedStringWithType:type]
                                        withKey:self.credentials.key];
}

- (NSString *)timestampSkewHmac {
        NSTimeInterval timeStamp = [self.timestamp timeIntervalSince1970];
        NSString *normalizedString
        = [NSString stringWithFormat:@"hawk.%@.ts\n%.0f\n", kHawkHeaderVersion, timeStamp];
        
        return [self.cryptoProxy hmacFromString:normalizedString withKey:self.credentials.key];
}

- (NSString *)bewit {
        NSString *hmac = [self hmacWithType:kHawkAuthTypeBewit];
        
        if (!self.ext) {
                _ext = @"";
        }
        
        NSString *normalizedString = [NSString stringWithFormat:@"%@\\%.0f\\%@\\%@",
                                      self.credentials.keyId,
                                      [self.timestamp timeIntervalSince1970],
                                      hmac,
                                      self.ext];
        
        NSString *bewit = [[normalizedString base64EncodedString] stringByTrimmingCharactersInSet:
                           [NSCharacterSet characterSetWithCharactersInString:@"="]];
        
        bewit = [bewit stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
        bewit = [bewit stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
        
        return bewit;
}

#pragma mark - Headers

- (NSString *)requestHeader {
        return [NSString stringWithFormat:@"%@: %@",
                self.requestHeaderKey,
                self.requestHeaderValue];
}

- (NSString *)requestHeaderKey {
        return @"Authorization";
}

- (NSString *)requestHeaderValue {
        NSMutableString *header = [NSMutableString string];
        
        [header appendString:[NSString stringWithFormat:@"Hawk id=\"%@\"", self.credentials.keyId]];
        [header appendString:[NSString stringWithFormat:@", mac=\"%@\"", [self hmacWithType:kHawkAuthTypeHeader]]];
        [header appendString:[NSString stringWithFormat:@", ts=\"%.0f\"", [self.timestamp timeIntervalSince1970]]];
        [header appendString:[NSString stringWithFormat:@", nonce=\"%@\"", self.nonce]];
        
        if (self.payload) {
                [header appendString:[NSString stringWithFormat:@", hash=\"%@\"", [self payloadHash]]];
        }
        
        if (self.app) {
                [header appendString:[NSString stringWithFormat:@", app=\"%@\"", self.app]];
        }
        
        if (self.ext) {
                [header appendString:[NSString stringWithFormat:@", ext=\"%@\"", self.ext]];
        }
        
        if (self.dlg) {
                [header appendString:[NSString stringWithFormat:@", dlg=\"%@\"", self.dlg]];
        }
        
        return [NSString stringWithString:header];
}

- (NSString *)responseHeader {
        return [NSString stringWithFormat:@"%@: %@",
                self.responseHeaderKey,
                self.responseHeaderValue];
}

- (NSString *)responseHeaderKey {
        return @"Server-Authorization";
}

- (NSString *)responseHeaderValue {
        NSMutableString *header = [NSMutableString string];
        
        [header appendFormat:@"Hawk mac=\"%@\"", [self hmacWithType:kHawkAuthTypeResponse]];
        
        if (self.payload) {
                [header appendFormat:@", hash=\"%@\"", [self payloadHash]];
        }
        
        return [NSString stringWithString:header];
}

- (NSString *)timestampSkewHeader {
        return [NSString stringWithFormat:@"%@: %@",
                self.timestampSkewHeaderKey,
                self.timestampSkewHeaderValue];
}

- (NSString *)timestampSkewHeaderKey {
        return @"WWW-Authenticate";
}

- (NSString *)timestampSkewHeaderValue {
        NSString *tsm = [self timestampSkewHmac];
        NSString *header = [NSString stringWithFormat:@"Hawk ts=\"%.0f\", tsm=\"%@\", error=\"timestamp skew too high\"",
                            [self.timestamp timeIntervalSince1970], tsm];
        
        return header;
}

#pragma mark -

- (NSDictionary *)parseAuthorizationHeader:(NSString *)header {
        NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
        
        // if this is not a hawk auth header, return an empty dictionary
        NSRange range = [header rangeOfString:@"Hawk "];
        if(range.location == NSNotFound) {
                return [NSDictionary dictionary];
        }
        
        NSString *attribString = [header substringFromIndex:range.location + range.length];
        NSArray *parts = [attribString componentsSeparatedByString:@","];
        
        NSString *key, *val;
        for (NSString *part in parts) {
                @try {
                        NSUInteger delimIndex = [part rangeOfString:@"="].location;
                        key = [part substringToIndex:delimIndex];
                        val = [part substringFromIndex:delimIndex + 1];
                        
                        key = [key stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                        val = [val stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"\\\""]];
                        
                        [attributes setValue:val forKey:key];
                        
                } @catch (NSException *exception) {
                        
                        continue; // if we get an out-of-bounds exception, try the next pair.
                }
        }
        
        return [NSDictionary dictionaryWithDictionary:attributes];
}

- (HawkError *)validateRequestHeader:(NSString *)header
                   credentialsLookup:(CredentialsLookupBlock)credentialsLookup {
        NSDictionary *headerAttributes = [self parseAuthorizationHeader:header];
        
        // id lookup
        NSString *keyId = [headerAttributes objectForKey:@"id"];
        
        if (!keyId) {
                return [HawkError hawkErrorWithReason:HawkErrorUnknownId];
        }
        
        HawkCredentials *credentials = credentialsLookup(keyId);
        
        if (!credentials) {
                return [HawkError hawkErrorWithReason:HawkErrorUnknownId];
        }
        
        // set attributes
        _credentials = credentials;
        
        _nonce = [headerAttributes objectForKey:@"nonce"];
        
        NSNumber* since1970 = [[NSNumberFormatter alloc] numberFromString:[headerAttributes objectForKey:@"ts"]];
        _timestamp = [[NSDate alloc] initWithTimeIntervalSince1970:[since1970 doubleValue]];
        
        _app = [headerAttributes objectForKey:@"app"];
        
        // validate payload hash
        NSString *hash = [headerAttributes objectForKey:@"hash"];
        if (hash) {
                NSString *expectedPayloadHash = [self payloadHash];
                
                if (![expectedPayloadHash isEqualToString:hash]) {
                        return [HawkError hawkErrorWithReason:HawkErrorInvalidPayloadHash];
                }
        }
        
        // validate hmac
        NSString *expectedMac = [self hmacWithType:kHawkAuthTypeHeader];
        NSString *mac = [headerAttributes objectForKey:@"mac"];
        
        if (![expectedMac isEqualToString:mac]) {
                return [HawkError hawkErrorWithReason:HawkErrorInvalidMac];
        }
        
        // valid
        return nil;
}

- (HawkError *)validateResponseHeader:(NSString *)header {
        NSDictionary *headerAttribtues = [self parseAuthorizationHeader:header];
        
        NSString *hash = [headerAttribtues objectForKey:@"hash"];
        
        // validate payload hash
        if (hash) {
                NSString *expectedHash = [self payloadHash];
                
                if (![expectedHash isEqualToString:hash]) {
                        return [HawkError hawkErrorWithReason:HawkErrorInvalidPayloadHash];
                }
        }
        
        // validate hmac
        NSString *mac = [headerAttribtues objectForKey:@"mac"];
        
        NSString *expectedMac = [self hmacWithType:kHawkAuthTypeResponse];
        
        if (![expectedMac isEqualToString:mac]) {
                return [HawkError hawkErrorWithReason:HawkErrorInvalidMac];
        }
        
        // valid
        return nil;
}

- (HawkError *)validateBewit:(NSString *)bewit
           credentialsLookup:(CredentialsLookupBlock)credentialsLookup
                  serverTime:(NSDate *)serverTime {
        // parse bewit
        NSString *padding = [[[NSString alloc] init] stringByPaddingToLength:((4 - bewit.length) % 4) withString:@"=" startingAtIndex:0];
        
        NSString *normalizedString = [[bewit stringByAppendingString:padding] base64DecodedString];
        
        NSArray *parts = [normalizedString componentsSeparatedByString:@"\\"];
        
        // id\ts\mac\ext
        if (parts.count != 4) {
                return [HawkError hawkErrorWithReason:HawkErrorMalformedBewit];
        }
        
        // id lookup
        NSString *keyId = [parts objectAtIndex:0];
        HawkCredentials *credentials = credentialsLookup(keyId);
        
        if (!credentials) {
                return [HawkError hawkErrorWithReason:HawkErrorUnknownId];
        }
        
        // set attributes
        _credentials = credentials;
        
        NSNumber* since1970 = [[NSNumberFormatter alloc] numberFromString:[parts objectAtIndex:1]];
        _timestamp = [[NSDate alloc] initWithTimeIntervalSince1970:[since1970 doubleValue]];
        
        _ext = [parts objectAtIndex:3];
        
        NSString *mac = [parts objectAtIndex:2];
        
        // validate timestamp
        if ([self.timestamp timeIntervalSince1970] > [serverTime timeIntervalSince1970]) {
                return [HawkError hawkErrorWithReason:HawkErrorBewitExpired];
        }
        
        // validate hmac
        NSString *expectedMac = [self hmacWithType:kHawkAuthTypeBewit];
        
        if (![expectedMac isEqualToString:mac]) {
                return [HawkError hawkErrorWithReason:HawkErrorInvalidMac];
        }
        
        // valid
        return nil;
}

@end

#pragma mark - Builder

@interface HawkAuthBuilder()
@property (nonatomic, strong) NSString *app;
@property (nonatomic, strong) NSString *contentType;
@property (nonatomic, strong) HawkCredentials *credentials;
@property (nonatomic, strong) NSString *dlg;
@property (nonatomic, strong) NSString *ext;
@property (nonatomic, strong) NSString *host;
@property (nonatomic, strong) NSString *method;
@property (nonatomic, strong) NSString *nonce;
@property (nonatomic, strong) NSString *payload;
@property (nonatomic, strong) NSNumber *port;
@property (nonatomic, strong) NSString *resourcePath;
@property (nonatomic, strong) NSDate *timestamp;
@end

@implementation HawkAuthBuilder

- (instancetype)initWithCredentials:(HawkCredentials *)credentials {
        if (self = [super init]) {
                _credentials = credentials;
        }
        return self;
}

+ (instancetype)withCredentials:(HawkCredentials *)credentials {
        return [[self alloc] initWithCredentials:credentials];
}

+ (instancetype)builder {
        return [self new];
}

+ (instancetype)withKeyId:(NSString *)keyId
                      key:(NSString *)key
                algorithm:(CryptoAlgorithm)algorithm {
        HawkCredentials *credentials = [HawkCredentials withKeyId:keyId
                                                              key:key
                                                        algorithm:algorithm];
        return [self withCredentials:credentials];
}

- (instancetype)withApp:(NSString *)applicationID {
        self.app = applicationID;
        return self;
}

- (instancetype)withContentType:(NSString *)contentType {
        self.contentType = contentType;
        return self;
}

- (instancetype)withCredentials:(HawkCredentials *)credentials {
        self.credentials = credentials;
        return self;
}

- (instancetype)withDlg:(NSString *)dlg {
        self.dlg = dlg;
        return self;
}

- (instancetype)withExt:(NSString *)ext {
        self.ext = ext;
        return self;
}

- (instancetype)withMethod:(NSString *)method {
        self.method = [method uppercaseString];
        return self;
}

- (instancetype)withNonce:(NSString *)nonce {
        self.nonce = nonce;
        return self;
}

- (instancetype)withPayload:(NSString *)payload {
        self.payload = payload;
        return self;
}

- (instancetype)withTimestamp:(NSDate *)timestamp {
        self.timestamp = timestamp;
        return self;
}

- (instancetype)withHost:(NSString *)host {
        self.host = host;
        return self;
}
- (instancetype)withPort:(NSNumber *)port {
        self.port = port;
        return self;
}

- (instancetype)withResourcePath:(NSString *)resourcePath {
        self.resourcePath = resourcePath;
        return self;
}

- (instancetype)withURL:(NSURL *)url {
        NSString *path = [NSString stringWithFormat:@"%@%@%@",
                          url.path,
                          url.query ? @"?" : @"",
                          url.query ?: @""];
        
        return [[[self withHost:url.host]
                 withPort:url.port]
                withResourcePath:path];
}

- (instancetype)withURLString:(NSString *)urlString {
        return [self withURL:[NSURL URLWithString:urlString]];
}

- (instancetype)switchAlgorithm:(CryptoAlgorithm)algorithm {
        self.credentials = [self.credentials copyWithAlgorithm:algorithm];
        return self;
}

- (instancetype)usingGET {
        return [self withMethod:@"GET"];
}

- (instancetype)usingPOST {
        return [self withMethod:@"POST"];
}

- (instancetype)usingPUT {
        return [self withMethod:@"PUT"];
}

- (instancetype)usingDELETE {
        return [self withMethod:@"DELETE"];
}

- (instancetype)usingContentType:(ContentType)contentType {
        switch (contentType) {
                case kContentTypeEmpty:
                        return [self withContentType:@""];
                case kContentTypeNil:
                        return [self withContentType:nil];
                        
                case kContentTypeTextHTML:
                        return [self withContentType:@"text/HTML"];
                case kContentTypeTextPlain:
                        return [self withContentType:@"text/plain"];
                case kContentTypeApplicationJSON:
                        return [self withContentType:@"application/json"];
                        
                //TODO: add moar
                        
                default:
                        NSAssert(NO, @"Unrecognized content type: %@", @(contentType));
                        return [self withContentType:nil];
        }
}

- (HawkAuth *)buildWithNonce:(NSString *)nonce {
        self.nonce = nonce;
        return [self build];
}

- (HawkAuth *)buildAndGenerateNonce {
        return [self buildWithNonce:[Nonce generate]];
}

- (HawkAuth *)build {
        HawkAuth *auth = [HawkAuth new];
        
        auth.app = self.app;
        auth.contentType = self.contentType;
        auth.credentials = self.credentials;
        auth.dlg = self.dlg;
        auth.ext = self.ext;
        auth.host = self.host;
        auth.method = self.method;
        auth.nonce = self.nonce;
        auth.payload = self.payload;
        auth.port = self.port;
        auth.resourcePath = self.resourcePath;
        auth.timestamp = self.timestamp;
        
        return auth;
}

@end
