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

    XCTAssertTrue([Hawk validateAuthorizationHeader:header hawkAuthAttributes:authAttributes credentialsLookup:^HawkCredentials *(NSString *hawkId) {
        if ([hawkId isEqualToString:authAttributes.credentials.hawkId]) {
            return authAttributes.credentials;
        } else {
            return nil;
        }
    } nonceLookup:^BOOL(NSString *nonce) {
        return NO;
    }]);
}

@end
