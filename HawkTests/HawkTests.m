//
//  HawkTests.m
//  HawkTests
//
//  Created by Jesse Stuart on 8/6/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "Hawk.h"


@interface HawkTests : XCTestCase
{
    HawkAuthAttributes *authAttributes;
}
@end

@implementation HawkTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.

    authAttributes = [[HawkAuthAttributes alloc] init];
    authAttributes.credentials = [[HawkCredentials alloc] initWithHawkId:@"exqbZWtykFZIh2D7cXi9dA" withKey:@"HX9QcbD-r3ItFEnRcAuOSg" withAlgorithm:@"sha256"];
    authAttributes.contentType = @"application/vnd.tent.post.v0+json";
    authAttributes.method = @"POST";
    authAttributes.requestUri = @"/posts";
    authAttributes.host = @"example.com";
    authAttributes.port = [[NSNumber alloc] initWithInt:443];
    authAttributes.payload = [@"{\"type\":\"https://tent.io/types/status/v0#\"}" dataUsingEncoding:NSUTF8StringEncoding];
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testPayloadHash
{
    NSString *expectedHash = @"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=";

    NSString *payloadHash = [Hawk payloadHashWithAttributes:authAttributes];

    XCTAssertEqualObjects(payloadHash, expectedHash);
}

- (void)testMac
{
    NSString *expectedMac = @"2sttHCQJG9ejj1x7eCi35FP23Miu9VtlaUgwk68DTpM=";

    authAttributes.app = @"wn6yzHGe5TLaT-fvOPbAyQ";
    authAttributes.nonce = @"3yuYCD4Z";
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *mac = [Hawk mac:authAttributes];

    XCTAssertEqualObjects(mac, expectedMac);
}

- (void)testServerAuthorizationMac
{
    NSString *expectedMac = @"lTG3kTBr33Y97Q4KQSSamu9WY/mOUKnZzq/ho9x+yxw=";

    authAttributes.app = @"wn6yzHGe5TLaT-fvOPbAyQ";
    authAttributes.nonce = @"3yuYCD4Z";
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];
    authAttributes.payload = nil;

    NSString *mac = [Hawk responseMac:authAttributes];

    XCTAssertEqualObjects(mac, expectedMac);
}

- (void)testServerAuthorizationMacWithPayload
{
    NSString *expectedMac = @"LvxASIZ2gop5cwE2mNervvz6WXkPmVslwm11MDgEZ5E=";

    authAttributes.nonce = @"3yuYCD4Z";
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *mac = [Hawk responseMac:authAttributes];

    XCTAssertEqualObjects(mac, expectedMac);
}

- (void)testBewit
{
    NSString *expectedBewit = @"ZXhxYlpXdHlrRlpJaDJEN2NYaTlkQVwxMzY4OTk2ODAwXE8wbWhwcmdvWHFGNDhEbHc1RldBV3ZWUUlwZ0dZc3FzWDc2dHBvNkt5cUk9XA";

    authAttributes.payload = nil;
    authAttributes.method = @"GET";
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *bewit = [Hawk bewit:authAttributes];

    XCTAssertEqualObjects(bewit, expectedBewit);
}

- (void) testBewitValidation
{
    NSString *bewit = @"ZXhxYlpXdHlrRlpJaDJEN2NYaTlkQVwxMzY4OTk2ODAwXE8wbWhwcmdvWHFGNDhEbHc1RldBV3ZWUUlwZ0dZc3FzWDc2dHBvNkt5cUk9XA";

    authAttributes.payload = nil;
    authAttributes.method = @"GET";

    HawkResponse *response = [Hawk validateBewit:bewit hawkAuthAttributes:authAttributes serverTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800] credentialsLookup:^HawkCredentials *(NSString *hawkId) {
        if ([hawkId isEqualToString:authAttributes.credentials.hawkId]) {
            return authAttributes.credentials;
        } else {
            return nil;
        }
    }];

    XCTAssert(!response.error);
    XCTAssertEqual(authAttributes.credentials, response.credentials);
}

- (void)testExpiredBewitValidation
{
    NSString *bewit = @"ZXhxYlpXdHlrRlpJaDJEN2NYaTlkQVwxMzY4OTk2ODAwXE8wbWhwcmdvWHFGNDhEbHc1RldBV3ZWUUlwZ0dZc3FzWDc2dHBvNkt5cUk9XA";

    authAttributes.payload = nil;
    authAttributes.method = @"GET";

    HawkResponse *response = [Hawk validateBewit:bewit hawkAuthAttributes:authAttributes serverTimestamp:[NSDate dateWithTimeIntervalSince1970:1368996800 - 1] credentialsLookup:^HawkCredentials *(NSString *hawkId) {
        if ([hawkId isEqualToString:authAttributes.credentials.hawkId]) {
            return authAttributes.credentials;
        } else {
            return nil;
        }
    }];

    XCTAssert(HawkErrorBewitExpired == response.error.errorReason);
    XCTAssert(!response.credentials);
}

- (void)testAuthorizationHeader
{
    NSString *expectedHeader = @"Authorization: Hawk id=\"exqbZWtykFZIh2D7cXi9dA\", mac=\"2sttHCQJG9ejj1x7eCi35FP23Miu9VtlaUgwk68DTpM=\", ts=\"1368996800\", nonce=\"3yuYCD4Z\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\", app=\"wn6yzHGe5TLaT-fvOPbAyQ\"";

    authAttributes.app = @"wn6yzHGe5TLaT-fvOPbAyQ";
    authAttributes.nonce = @"3yuYCD4Z";
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *header = [Hawk authorizationHeader:authAttributes];

    XCTAssertEqualObjects(header, expectedHeader);
}

- (void)testAuthorizationHeaderValidation
{
    NSString *header = @"Authorization: Hawk id=\"exqbZWtykFZIh2D7cXi9dA\", mac=\"2sttHCQJG9ejj1x7eCi35FP23Miu9VtlaUgwk68DTpM=\", ts=\"1368996800\", nonce=\"3yuYCD4Z\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\", app=\"wn6yzHGe5TLaT-fvOPbAyQ\"";

    HawkResponse *response = [Hawk validateAuthorizationHeader:header hawkAuthAttributes:authAttributes credentialsLookup:^HawkCredentials *(NSString *hawkId) {
        if ([hawkId isEqualToString:authAttributes.credentials.hawkId]) {
            return authAttributes.credentials;
        } else {
            return nil;
        }
    } nonceLookup:^BOOL(NSString *nonce) {
        return NO;
    }];

    XCTAssertEqualObjects(authAttributes.credentials, response.credentials);
    XCTAssert(!response.error);
}

- (void)testServerAuthorizationHeader
{
    NSString *expectedHeader = @"Server-Authorization: Hawk mac=\"lTG3kTBr33Y97Q4KQSSamu9WY/mOUKnZzq/ho9x+yxw=\"";

    authAttributes.app = @"wn6yzHGe5TLaT-fvOPbAyQ";
    authAttributes.nonce = @"3yuYCD4Z";
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];
    authAttributes.payload = nil;

    NSString *header = [Hawk serverAuthorizationHeader:authAttributes];

    XCTAssertEqualObjects(header, expectedHeader);
}

- (void)testServerAuthorizationHeaderWithPayload
{
    NSString *expectedHeader = @"Server-Authorization: Hawk mac=\"LvxASIZ2gop5cwE2mNervvz6WXkPmVslwm11MDgEZ5E=\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\"";

    authAttributes.nonce = @"3yuYCD4Z";
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *header = [Hawk serverAuthorizationHeader:authAttributes];

    XCTAssertEqualObjects(header, expectedHeader);
}

- (void)testServerAuthorizationHeaderValidation
{
    NSString *header = @"Server-Authorization: Hawk mac=\"lTG3kTBr33Y97Q4KQSSamu9WY/mOUKnZzq/ho9x+yxw=\"";

    authAttributes.app = @"wn6yzHGe5TLaT-fvOPbAyQ";
    authAttributes.nonce = @"3yuYCD4Z";
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];
    authAttributes.payload = nil;

    HawkResponse *response = [Hawk validateServerAuthorizationHeader:header hawkAuthAttributes:authAttributes];

    XCTAssert(!response.error);
    XCTAssertEqualObjects(authAttributes.credentials, response.credentials);
}

- (void)testServerAuthorizationHeaderWithPayloadValidation
{
    NSString *header = @"Server-Authorization: Hawk mac=\"LvxASIZ2gop5cwE2mNervvz6WXkPmVslwm11MDgEZ5E=\", hash=\"neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=\"";

    authAttributes.nonce = @"3yuYCD4Z";
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    HawkResponse *response = [Hawk validateServerAuthorizationHeader:header hawkAuthAttributes:authAttributes];

    XCTAssert(!response.error);
    XCTAssertEqualObjects(authAttributes.credentials, response.credentials);
}

- (void)testTimestampSkew
{
    NSString *expectedTsm = @"HPDcD5S3Kw7LM/oyoXKcgv2Z30RnOLAI5ebXpYDGfo4=";

    HawkCredentials *credentials = authAttributes.credentials;
    authAttributes = [[HawkAuthAttributes alloc] init];
    authAttributes.credentials = credentials;
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *tsm = [Hawk timestampSkewMac:authAttributes];

    XCTAssertEqualObjects(expectedTsm, tsm);
}

- (void)testTimestampSkewHeader
{
    NSString *expectedHeader = @"WWW-Authenticate: Hawk ts=\"1368996800\", tsm=\"HPDcD5S3Kw7LM/oyoXKcgv2Z30RnOLAI5ebXpYDGfo4=\", error=\"timestamp skew too high\"";

    HawkCredentials *credentials = authAttributes.credentials;
    authAttributes = [[HawkAuthAttributes alloc] init];
    authAttributes.credentials = credentials;
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1368996800];

    NSString *header = [Hawk timestampSkewHeader:authAttributes];

    XCTAssertEqualObjects(expectedHeader, header);
}

@end
