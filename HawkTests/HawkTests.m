//
//  HawkTests.m
//  HawkTests
//
//  Created by Jesse Stuart on 8/6/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "HawkAuth.h"
#import "NSData+Base64.h"

@interface HawkTests : XCTestCase
{
    HawkAuth *auth;
}
@end

@implementation HawkTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.

    auth = [[HawkAuth alloc] init];
    auth.credentials = [[HawkCredentials alloc] initWithHawkId:@"exqbZWtykFZIh2D7cXi9dA" withKey:@"HX9QcbD-r3ItFEnRcAuOSg" withAlgorithm:CryptoAlgorithmSHA256];
    auth.contentType = @"application/vnd.tent.post.v0+json";
    auth.method = @"POST";
    auth.requestUri = @"/posts";
    auth.host = @"example.com";
    auth.port = [[NSNumber alloc] initWithInt:443];
    auth.payload = [@"{\"type\":\"https://tent.io/types/status/v0#\"}" dataUsingEncoding:NSUTF8StringEncoding];
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testPayloadHash
{
    NSString *expectedHash = @"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=";

    NSString *payloadHash = [auth payloadHash];

    XCTAssertEqualObjects(payloadHash, expectedHash);
}

- (void)testMac
{
    NSString *expectedMac = @"2sttHCQJG9ejj1x7eCi35FP23Miu9VtlaUgwk68DTpM=";

    auth.app = @"wn6yzHGe5TLaT-fvOPbAyQ";
    auth.nonce = @"3yuYCD4Z";
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *mac = [auth hmacWithType:HawkAuthTypeHeader];

    XCTAssertEqualObjects(mac, expectedMac);
}

- (void)testServerAuthorizationMac
{
    NSString *expectedMac = @"lTG3kTBr33Y97Q4KQSSamu9WY/mOUKnZzq/ho9x+yxw=";

    auth.app = @"wn6yzHGe5TLaT-fvOPbAyQ";
    auth.nonce = @"3yuYCD4Z";
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];
    auth.payload = nil;

    NSString *mac = [auth hmacWithType:HawkAuthTypeResponse];

    XCTAssertEqualObjects(mac, expectedMac);
}

- (void)testServerAuthorizationMacWithPayload
{
    NSString *expectedMac = @"LvxASIZ2gop5cwE2mNervvz6WXkPmVslwm11MDgEZ5E=";

    auth.nonce = @"3yuYCD4Z";
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *mac = [auth hmacWithType:HawkAuthTypeResponse];

    XCTAssertEqualObjects(mac, expectedMac);
}

- (void)testBewit
{
    // First Test Vector (doesn't ensure urlsafe base64 fn used)
    NSString *expectedBewit = @"ZXhxYlpXdHlrRlpJaDJEN2NYaTlkQVwxMzY4OTk2ODAwXE8wbWhwcmdvWHFGNDhEbHc1RldBV3ZWUUlwZ0dZc3FzWDc2dHBvNkt5cUk9XA";

    auth.payload = nil;
    auth.method = @"GET";
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *bewit = [auth bewit];

    XCTAssertEqualObjects(bewit, expectedBewit);

    // Second Test Vector (ensures far future timestamps work, "/" is replaced with "_")
    expectedBewit = @"MTIzNDU2XDQ1MTkzMTE0NThcRDk0L0daVEwzbFpvSmx6cnBLZUtZWkswd3NzS21FalNrSStFZm51dHh1QT1c76u_77yw44Sy";

    auth = [[HawkAuth alloc] init];
    auth.credentials = [[HawkCredentials alloc] initWithHawkId:@"123456" withKey:@"2983d45yun89q" withAlgorithm:CryptoAlgorithmSHA256];

    auth.method = @"GET";
    auth.requestUri = @"/resource/4?a=1&b=2";
    auth.port = [NSNumber numberWithInt:80];
    auth.host = @"example.com";
    auth.ext = [[NSString alloc] initWithData:[NSData dataWithBase64EncodedString:@"76u/77yw44Sy\n"] encoding:NSUTF8StringEncoding];
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:4519311458];

    bewit = [auth bewit];

    XCTAssertEqualObjects(bewit, expectedBewit);
}

- (void) testBewitValidation
{
    NSString *bewit = @"ZXhxYlpXdHlrRlpJaDJEN2NYaTlkQVwxMzY4OTk2ODAwXE8wbWhwcmdvWHFGNDhEbHc1RldBV3ZWUUlwZ0dZc3FzWDc2dHBvNkt5cUk9XA";

    auth.payload = nil;
    auth.method = @"GET";

    HawkError *error = [auth validateBewit:bewit credentialsLookup:^HawkCredentials *(NSString * hawkId) {
        if ([hawkId isEqualToString:auth.credentials.hawkId]) {
            return auth.credentials;
        } else {
            return nil;
        }
    } serverTime:[NSDate dateWithTimeIntervalSince1970:1368996800]];

    XCTAssert(!error);
}

- (void)testExpiredBewitValidation
{
    NSString *bewit = @"ZXhxYlpXdHlrRlpJaDJEN2NYaTlkQVwxMzY4OTk2ODAwXE8wbWhwcmdvWHFGNDhEbHc1RldBV3ZWUUlwZ0dZc3FzWDc2dHBvNkt5cUk9XA";

    auth.payload = nil;
    auth.method = @"GET";

    HawkError *error = [auth validateBewit:bewit credentialsLookup:^HawkCredentials *(NSString * hawkId) {
        if ([hawkId isEqualToString:auth.credentials.hawkId]) {
            return auth.credentials;
        } else {
            return nil;
        }
    } serverTime:[NSDate dateWithTimeIntervalSince1970:1368996800-1]];

    XCTAssertNotNil(error);
}

- (void)testAuthorizationHeader
{
    NSString *expectedHeader = @"Authorization: Hawk id=\"exqbZWtykFZIh2D7cXi9dA\", mac=\"2sttHCQJG9ejj1x7eCi35FP23Miu9VtlaUgwk68DTpM=\", ts=\"1368996800\", nonce=\"3yuYCD4Z\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\", app=\"wn6yzHGe5TLaT-fvOPbAyQ\"";

    auth.app = @"wn6yzHGe5TLaT-fvOPbAyQ";
    auth.nonce = @"3yuYCD4Z";
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *header = [auth requestHeader];

    XCTAssertEqualObjects(header, expectedHeader);
}

- (void)testAuthorizationHeaderValidation
{
    NSString *header = @"Authorization: Hawk id=\"exqbZWtykFZIh2D7cXi9dA\", mac=\"2sttHCQJG9ejj1x7eCi35FP23Miu9VtlaUgwk68DTpM=\", ts=\"1368996800\", nonce=\"3yuYCD4Z\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\", app=\"wn6yzHGe5TLaT-fvOPbAyQ\"";

    HawkError *error = [auth validateRequestHeader:header credentialsLookup:^HawkCredentials *(NSString *hawkId) {
        if ([hawkId isEqualToString:auth.credentials.hawkId]) {
            return auth.credentials;
        }

        return nil;
    }];

    XCTAssert(!error);
}

- (void)testServerAuthorizationHeader
{
    NSString *expectedHeader = @"Server-Authorization: Hawk mac=\"lTG3kTBr33Y97Q4KQSSamu9WY/mOUKnZzq/ho9x+yxw=\"";

    auth.app = @"wn6yzHGe5TLaT-fvOPbAyQ";
    auth.nonce = @"3yuYCD4Z";
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];
    auth.payload = nil;

    NSString *header = [auth responseHeader];

    XCTAssertEqualObjects(header, expectedHeader);
}

- (void)testServerAuthorizationHeaderWithPayload
{
    NSString *expectedHeader = @"Server-Authorization: Hawk mac=\"LvxASIZ2gop5cwE2mNervvz6WXkPmVslwm11MDgEZ5E=\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\"";

    auth.nonce = @"3yuYCD4Z";
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *header = [auth responseHeader];

    XCTAssertEqualObjects(header, expectedHeader);
}

- (void)testServerAuthorizationHeaderValidation
{
    NSString *header = @"Server-Authorization: Hawk mac=\"lTG3kTBr33Y97Q4KQSSamu9WY/mOUKnZzq/ho9x+yxw=\"";

    auth.app = @"wn6yzHGe5TLaT-fvOPbAyQ";
    auth.nonce = @"3yuYCD4Z";
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];
    auth.payload = nil;

    HawkError *error = [auth validateResponseHeader:header];

    XCTAssert(!error);
}

- (void)testServerAuthorizationHeaderWithPayloadValidation
{
    NSString *header = @"Server-Authorization: Hawk mac=\"LvxASIZ2gop5cwE2mNervvz6WXkPmVslwm11MDgEZ5E=\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\"";

    auth.nonce = @"3yuYCD4Z";
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    HawkError *error = [auth validateResponseHeader:header];

    XCTAssert(!error);
}

- (void)testTimestampSkew
{
    NSString *expectedTsm = @"HPDcD5S3Kw7LM/oyoXKcgv2Z30RnOLAI5ebXpYDGfo4=";

    HawkCredentials *credentials = auth.credentials;
    auth = [[HawkAuth alloc] init];
    auth.credentials = credentials;
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *tsm = [auth timestampSkewHmac];

    XCTAssertEqualObjects(expectedTsm, tsm);
}

- (void)testTimestampSkewHeader
{
    NSString *expectedHeader = @"WWW-Authenticate: Hawk ts=\"1368996800\", tsm=\"HPDcD5S3Kw7LM/oyoXKcgv2Z30RnOLAI5ebXpYDGfo4=\", error=\"timestamp skew too high\"";

    HawkCredentials *credentials = auth.credentials;
    auth = [[HawkAuth alloc] init];
    auth.credentials = credentials;
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *header = [auth timestampSkewHeader];

    XCTAssertEqualObjects(expectedHeader, header);
}

@end
