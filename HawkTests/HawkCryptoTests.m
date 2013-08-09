//
//  HawkCryptoTests.m
//  HawkCryptoTests
//
//  Created by Jesse Stuart on 8/9/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "Hawk.h"


@interface HawkCryptoTests : XCTestCase
@end

@implementation HawkCryptoTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testPayloadHashWith
{
    // Common setup
    HawkAuthAttributes *authAttributes = [[HawkAuthAttributes alloc] init];
    authAttributes.credentials = [[HawkCredentials alloc] initWithHawkId:@"123456" withKey:@"2983d45yun89q" withAlgorithm:CryptoAlgorithmSHA256];
    authAttributes.contentType = @"";
    authAttributes.payload = [@"something to write about" dataUsingEncoding:NSUTF8StringEncoding];

    NSString *expectedHash;
    NSString *actualHash;

    // SHA1
    authAttributes.credentials.algorithm = CryptoAlgorithmSHA1;
    expectedHash = @"bsvY3IfUllw6V5rvk4tStEvpBhE=";
    actualHash = [Hawk payloadHashWithAttributes:authAttributes].value;

    XCTAssertEqualObjects(actualHash, expectedHash);

    // SHA256
    authAttributes.credentials.algorithm = CryptoAlgorithmSHA256;
    expectedHash = @"LjRmtkSKTW0ObTUyZ7N+vjClKd//KTTdfhF1M4XCuEM=";
    actualHash = [Hawk payloadHashWithAttributes:authAttributes].value;

    XCTAssertEqualObjects(actualHash, expectedHash);
}

- (void)testBewit
{
    HawkAuthAttributes *authAttributes = [[HawkAuthAttributes alloc] init];
    authAttributes.credentials = [[HawkCredentials alloc] initWithHawkId:@"123456" withKey:@"2983d45yun89q" withAlgorithm:CryptoAlgorithmSHA256];
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:4519311458];
    authAttributes.method = @"GET";
    authAttributes.requestUri = @"/resource/4?a=1&b=2";
    authAttributes.host = @"example.com";
    authAttributes.port = [NSNumber numberWithInt:80];
    authAttributes.ext = @"some-app-data";

    NSString *expectedBewit = @"MTIzNDU2XDQ1MTkzMTE0NThcYkkwanFlS1prUHE0V1hRMmkxK0NrQ2lOanZEc3BSVkNGajlmbElqMXphWT1cc29tZS1hcHAtZGF0YQ";
    NSString *actualBewit = [Hawk bewit:authAttributes].value;

    XCTAssertEqualObjects(actualBewit, expectedBewit);
}

- (void)testMac
{
    // Common setup
    HawkAuthAttributes *authAttributes = [[HawkAuthAttributes alloc] init];
    authAttributes.credentials = [[HawkCredentials alloc] initWithHawkId:@"123456" withKey:@"2983d45yun89q" withAlgorithm:CryptoAlgorithmSHA256];
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1353809207];
    authAttributes.contentType = @"";
    authAttributes.method = @"POST";
    authAttributes.requestUri = @"/somewhere/over/the/rainbow";
    authAttributes.host = @"example.net";
    authAttributes.port = [NSNumber numberWithInt:80];
    authAttributes.payload = [@"something to write about" dataUsingEncoding:NSUTF8StringEncoding];
    authAttributes.ext = @"Bazinga!";
    authAttributes.nonce = @"Ygvqdz";

    NSString *expectedMac;
    NSString *actualMac;

    // SHA1
    authAttributes.credentials.algorithm = CryptoAlgorithmSHA1;
    expectedMac = @"qbf1ZPG/r/e06F4ht+T77LXi5vw=";
    actualMac = [Hawk mac:authAttributes].value;

    XCTAssertEqualObjects(actualMac, expectedMac);

    // SHA256
    authAttributes.credentials.algorithm = CryptoAlgorithmSHA256;
    expectedMac = @"dh5kEkotNusOuHPolRYUhvy2vlhJybTC2pqBdUQk5z0=";
    actualMac = [Hawk mac:authAttributes].value;

    XCTAssertEqualObjects(actualMac, expectedMac);
}

- (void)timestampSkewMac
{
    HawkAuthAttributes *authAttributes = [[HawkAuthAttributes alloc] init];
    authAttributes.credentials = [[HawkCredentials alloc] initWithHawkId:@"123456" withKey:@"2983d45yun89q" withAlgorithm:CryptoAlgorithmSHA256];
    authAttributes.timestamp = [NSDate dateWithTimeIntervalSince1970:1365741469];

    NSString *expectedMac = @"h/Ff6XI1euObD78ZNflapvLKXGuaw1RiLI4Q6Q5sAbM=";
    NSString *actualMac = [Hawk timestampSkewMac:authAttributes].value;

    XCTAssertEqualObjects(actualMac, expectedMac);
}

@end