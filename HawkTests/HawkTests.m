//
//  HawkTests.m
//  HawkTests
//
//  Created by Jesse Stuart on 8/6/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "HawkAuth.h"
#import "NSString+Base64.h"

@interface HawkTests : XCTestCase
@property (nonatomic, strong) HawkAuthBuilder *builder;
@property (nonatomic, strong) HawkAuth *auth;
@end

@implementation HawkTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
        
        HawkCredentials *creds = [HawkCredentials withKeyId:@"exqbZWtykFZIh2D7cXi9dA"
                                                        key:@"HX9QcbD-r3ItFEnRcAuOSg"
                                                  algorithm:kCryptoAlgorithmSHA256];
        self.builder = [[[[[HawkAuthBuilder withCredentials:creds]
                           withContentType:@"application/vnd.tent.post.v0+json"]
                          usingPOST]
                         withURLString:@"example.com:443/posts"]
                        withPayload:@"{\"type\":\"https://tent.io/types/status/v0#\"}"];
        
        self.auth = [self.builder build];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testPayloadHash {
    NSString *expectedHash = @"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=";

    NSString *payloadHash = [self.auth payloadHash];

    XCTAssertEqualObjects(payloadHash, expectedHash);
}

- (void)testMac {
    NSString *expectedMac = @"2sttHCQJG9ejj1x7eCi35FP23Miu9VtlaUgwk68DTpM=";

        self.auth = [[[[self.builder withApp:@"wn6yzHGe5TLaT-fvOPbAyQ"]
                       withNonce:@"3yuYCD4Z"]
                      withTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800]]
                     build];

    NSString *mac = [self.auth hmacWithType:kHawkAuthTypeHeader];

    XCTAssertEqualObjects(mac, expectedMac);
}

- (void)testServerAuthorizationMac
{
    NSString *expectedMac = @"lTG3kTBr33Y97Q4KQSSamu9WY/mOUKnZzq/ho9x+yxw=";

        self.auth = [[[[[self.builder withApp:@"wn6yzHGe5TLaT-fvOPbAyQ"]
                        withNonce:@"3yuYCD4Z"]
                       withTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800]]
                      withPayload:nil]
                     build];

    NSString *mac = [self.auth hmacWithType:kHawkAuthTypeResponse];

    XCTAssertEqualObjects(mac, expectedMac);
}

- (void)testServerAuthorizationMacWithPayload
{
    NSString *expectedMac = @"LvxASIZ2gop5cwE2mNervvz6WXkPmVslwm11MDgEZ5E=";

        self.auth = [[[self.builder withNonce:@"3yuYCD4Z"]
                      withTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800]]
                     build];

    NSString *mac = [self.auth hmacWithType:kHawkAuthTypeResponse];

    XCTAssertEqualObjects(mac, expectedMac);
}

- (void)testBewit {
    // First Test Vector (doesn't ensure urlsafe base64 fn used)
    NSString *expectedBewit = @"ZXhxYlpXdHlrRlpJaDJEN2NYaTlkQVwxMzY4OTk2ODAwXE8wbWhwcmdvWHFGNDhEbHc1RldBV3ZWUUlwZ0dZc3FzWDc2dHBvNkt5cUk9XA";
        
        self.auth = [[[[self.builder withPayload:nil]
                       usingGET]
                      withTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800]]
                     build];

    NSString *bewit = [self.auth bewit];

    XCTAssertEqualObjects(bewit, expectedBewit);

    // Second Test Vector (ensures far future timestamps work, "/" is replaced with "_")
    expectedBewit = @"MTIzNDU2XDQ1MTkzMTE0NThcRDk0L0daVEwzbFpvSmx6cnBLZUtZWkswd3NzS21FalNrSStFZm51dHh1QT1c76u_77yw44Sy";

    HawkCredentials *credentials = [HawkCredentials withKeyId:@"123456"
                                                          key:@"2983d45yun89q"
                                                    algorithm:kCryptoAlgorithmSHA256];
        

        self.auth = [[[[[[self.builder withCredentials:credentials]
                         usingGET]
                        withURLString:@"example.com:80/resource/4?a=1&b=2"]
                       withExt:[@"76u/77yw44Sy\n" base64DecodedString]]
                      withTimestamp:[NSDate dateWithTimeIntervalSince1970:4519311458]]
                     build];

    bewit = [self.auth bewit];

    XCTAssertEqualObjects(bewit, expectedBewit);
}

- (void) testBewitValidation {
    NSString *bewit = @"ZXhxYlpXdHlrRlpJaDJEN2NYaTlkQVwxMzY4OTk2ODAwXE8wbWhwcmdvWHFGNDhEbHc1RldBV3ZWUUlwZ0dZc3FzWDc2dHBvNkt5cUk9XA";

        self.auth = [[[self.builder withPayload:nil] usingGET] build];

    HawkError *error = [self.auth validateBewit:bewit
                              credentialsLookup:^HawkCredentials *(NSString *keyId) {
        if ([keyId isEqualToString:self.auth.credentials.keyId]) {
            return self.auth.credentials;
        } else {
            return nil;
        }
    } serverTime:[NSDate dateWithTimeIntervalSince1970:1368996800]];

    XCTAssert(!error);
}

- (void)testExpiredBewitValidation {
    NSString *bewit = @"ZXhxYlpXdHlrRlpJaDJEN2NYaTlkQVwxMzY4OTk2ODAwXE8wbWhwcmdvWHFGNDhEbHc1RldBV3ZWUUlwZ0dZc3FzWDc2dHBvNkt5cUk9XA";

    self.auth = [[[self.builder withPayload:nil] usingGET] build];

    HawkError *error = [self.auth validateBewit:bewit
                              credentialsLookup:^HawkCredentials *(NSString *keyId) {
        if ([keyId isEqualToString:self.auth.credentials.keyId]) {
            return self.auth.credentials;
        } else {
            return nil;
        }
    } serverTime:[NSDate dateWithTimeIntervalSince1970:1368996800-1]];

    XCTAssertNotNil(error);
}

- (void)testAuthorizationHeader {
    NSString *expectedHeader = @"Authorization: Hawk id=\"exqbZWtykFZIh2D7cXi9dA\", mac=\"2sttHCQJG9ejj1x7eCi35FP23Miu9VtlaUgwk68DTpM=\", ts=\"1368996800\", nonce=\"3yuYCD4Z\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\", app=\"wn6yzHGe5TLaT-fvOPbAyQ\"";

        self.auth = [[[[self.builder withApp:@"wn6yzHGe5TLaT-fvOPbAyQ"]
                       withNonce: @"3yuYCD4Z"]
                      withTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800]]
                     build];

    NSString *header = [self.auth requestHeader];

    XCTAssertEqualObjects(header, expectedHeader);
}

- (void)testAuthorizationHeaderValidation {
    NSString *header = @"Authorization: Hawk id=\"exqbZWtykFZIh2D7cXi9dA\", mac=\"2sttHCQJG9ejj1x7eCi35FP23Miu9VtlaUgwk68DTpM=\", ts=\"1368996800\", nonce=\"3yuYCD4Z\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\", app=\"wn6yzHGe5TLaT-fvOPbAyQ\"";

    HawkError *error = [self.auth validateRequestHeader:header
                                      credentialsLookup:^HawkCredentials *(NSString *keyId) {
        if ([keyId isEqualToString:self.auth.credentials.keyId]) {
            return self.auth.credentials;
        }

        return nil;
    }];

    XCTAssert(!error);
}

- (void)testServerAuthorizationHeader {
    NSString *expectedHeader = @"Server-Authorization: Hawk mac=\"lTG3kTBr33Y97Q4KQSSamu9WY/mOUKnZzq/ho9x+yxw=\"";
        
        self.auth = [[[[[self.builder withApp:@"wn6yzHGe5TLaT-fvOPbAyQ"]
                        withNonce:@"3yuYCD4Z"]
                       withTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800]]
                      withPayload:nil]
                     build];

    NSString *header = [self.auth responseHeader];

    XCTAssertEqualObjects(header, expectedHeader);
}

- (void)testServerAuthorizationHeaderWithPayload {
    NSString *expectedHeader = @"Server-Authorization: Hawk mac=\"LvxASIZ2gop5cwE2mNervvz6WXkPmVslwm11MDgEZ5E=\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\"";
        
        self.auth = [[[self.builder withNonce:@"3yuYCD4Z"]
                      withTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800]]
                     build];

    NSString *header = [self.auth responseHeader];

    XCTAssertEqualObjects(header, expectedHeader);
}

- (void)testServerAuthorizationHeaderValidation {
    NSString *header = @"Server-Authorization: Hawk mac=\"lTG3kTBr33Y97Q4KQSSamu9WY/mOUKnZzq/ho9x+yxw=\"";
        
        self.auth = [[[[[self.builder withApp:@"wn6yzHGe5TLaT-fvOPbAyQ"]
                        withNonce:@"3yuYCD4Z"]
                       withTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800]]
                      withPayload:nil]
                     build];

    HawkError *error = [self.auth validateResponseHeader:header];

    XCTAssert(!error);
}

- (void)testServerAuthorizationHeaderWithPayloadValidation {
    NSString *header = @"Server-Authorization: Hawk mac=\"LvxASIZ2gop5cwE2mNervvz6WXkPmVslwm11MDgEZ5E=\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\"";
        
        self.auth = [[[self.builder withNonce:@"3yuYCD4Z"]
                      withTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800]]
                     build];

    HawkError *error = [self.auth validateResponseHeader:header];

    XCTAssert(!error);
}

- (void)testTimestampSkew {
    NSString *expectedTsm = @"HPDcD5S3Kw7LM/oyoXKcgv2Z30RnOLAI5ebXpYDGfo4=";
        
        self.auth  = [[self.builder withTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800]]
                      build];

    NSString *tsm = [self.auth timestampSkewHmac];

    XCTAssertEqualObjects(expectedTsm, tsm);
}

- (void)testTimestampSkewHeader {
    NSString *expectedHeader = @"WWW-Authenticate: Hawk ts=\"1368996800\", tsm=\"HPDcD5S3Kw7LM/oyoXKcgv2Z30RnOLAI5ebXpYDGfo4=\", error=\"timestamp skew too high\"";

        self.auth = [[self.builder withTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800]]
                     build];
    

    NSString *header = [self.auth timestampSkewHeader];

    XCTAssertEqualObjects(expectedHeader, header);
}

@end
