//
//  HawkCryptoTests.m
//  HawkCryptoTests
//
//  Created by Jesse Stuart on 8/9/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "HawkAuth.h"

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
    HawkAuth *auth = [[HawkAuth alloc] init];
    auth.credentials = [[HawkCredentials alloc] initWithHawkId:@"123456" withKey:@"2983d45yun89q" withAlgorithm:CryptoAlgorithmSHA256];
    auth.contentType = @"";
    auth.payload = [@"something to write about" dataUsingEncoding:NSUTF8StringEncoding];

    NSString *expectedHash;
    NSString *actualHash;

    // SHA1
    auth.credentials.algorithm = CryptoAlgorithmSHA1;
    expectedHash = @"bsvY3IfUllw6V5rvk4tStEvpBhE=";
    actualHash = [auth payloadHash];

    XCTAssertEqualObjects(actualHash, expectedHash);

    // SHA256
    auth.credentials.algorithm = CryptoAlgorithmSHA256;
    expectedHash = @"LjRmtkSKTW0ObTUyZ7N+vjClKd//KTTdfhF1M4XCuEM=";
    actualHash = [auth payloadHash];

    XCTAssertEqualObjects(actualHash, expectedHash);
}

- (void)testPayloadHashWithComplexContentType
{
    // Common setup
    HawkAuth *auth = [[HawkAuth alloc] init];
    auth.credentials = [[HawkCredentials alloc] initWithHawkId:@"" withKey:@"" withAlgorithm:CryptoAlgorithmSHA256];
    auth.contentType = @"text/plain; type=\"something\"";
    auth.payload = [@"Something to write about" dataUsingEncoding:NSUTF8StringEncoding];

    NSString *expectedHash;
    NSString *actualHash;

    // SHA1
    auth.credentials.algorithm = CryptoAlgorithmSHA1;
    expectedHash = @"s3exeO2OBG5Q198BIN1HvEsbVB4=";
    actualHash = [auth payloadHash];

    XCTAssertEqualObjects(actualHash, expectedHash);

    // SHA256
    auth.credentials.algorithm = CryptoAlgorithmSHA256;
    expectedHash = @"RBzsyF5kNxkvMWvOKj90ULW1LHqOwqRo1sAEjjUkPuo=";
    actualHash = [auth payloadHash];

    XCTAssertEqualObjects(actualHash, expectedHash);
}

- (void)testPayloadHashWithWhiteSpaceInContentType
{
    // Common setup
    HawkAuth *auth = [[HawkAuth alloc] init];
    auth.credentials = [[HawkCredentials alloc] initWithHawkId:@"" withKey:@"" withAlgorithm:CryptoAlgorithmSHA256];
    auth.contentType = @" text/plain ; type=\"something\"";
    auth.payload = [@"Something to write about" dataUsingEncoding:NSUTF8StringEncoding];

    NSString *expectedHash;
    NSString *actualHash;

    // SHA1
    auth.credentials.algorithm = CryptoAlgorithmSHA1;
    expectedHash = @"s3exeO2OBG5Q198BIN1HvEsbVB4=";
    actualHash = [auth payloadHash];

    XCTAssertEqualObjects(actualHash, expectedHash);

    // SHA256
    auth.credentials.algorithm = CryptoAlgorithmSHA256;
    expectedHash = @"RBzsyF5kNxkvMWvOKj90ULW1LHqOwqRo1sAEjjUkPuo=";
    actualHash = [auth payloadHash];

    XCTAssertEqualObjects(actualHash, expectedHash);
}

- (void)testBewit
{
    HawkAuth *auth = [[HawkAuth alloc] init];
    auth.credentials = [[HawkCredentials alloc] initWithHawkId:@"123456" withKey:@"2983d45yun89q" withAlgorithm:CryptoAlgorithmSHA256];
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:4519311458];
    auth.method = @"GET";
    auth.requestUri = @"/resource/4?a=1&b=2";
    auth.host = @"example.com";
    auth.port = [NSNumber numberWithInt:80];
    auth.ext = @"some-app-data";

    NSString *expectedBewit = @"MTIzNDU2XDQ1MTkzMTE0NThcYkkwanFlS1prUHE0V1hRMmkxK0NrQ2lOanZEc3BSVkNGajlmbElqMXphWT1cc29tZS1hcHAtZGF0YQ";
    NSString *actualBewit = [auth bewit];

    XCTAssertEqualObjects(actualBewit, expectedBewit);
}

- (void)testMac
{
    // Common setup
    HawkAuth *auth = [[HawkAuth alloc] init];
    auth.credentials = [[HawkCredentials alloc] initWithHawkId:@"123456" withKey:@"2983d45yun89q" withAlgorithm:CryptoAlgorithmSHA256];
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1353809207];
    auth.contentType = @"";
    auth.method = @"POST";
    auth.requestUri = @"/somewhere/over/the/rainbow";
    auth.host = @"example.net";
    auth.port = [NSNumber numberWithInt:80];
    auth.payload = [@"something to write about" dataUsingEncoding:NSUTF8StringEncoding];
    auth.ext = @"Bazinga!";
    auth.nonce = @"Ygvqdz";

    NSString *expectedMac;
    NSString *actualMac;

    // SHA1
    auth.credentials.algorithm = CryptoAlgorithmSHA1;
    expectedMac = @"qbf1ZPG/r/e06F4ht+T77LXi5vw=";
    actualMac = [auth hmacWithType:HawkAuthTypeHeader];

    XCTAssertEqualObjects(actualMac, expectedMac);

    // SHA256
    auth.credentials.algorithm = CryptoAlgorithmSHA256;
    expectedMac = @"dh5kEkotNusOuHPolRYUhvy2vlhJybTC2pqBdUQk5z0=";
    actualMac = [auth hmacWithType:HawkAuthTypeHeader];

    XCTAssertEqualObjects(actualMac, expectedMac);
}

- (void)timestampSkewMac
{
    HawkAuth *auth = [[HawkAuth alloc] init];
    auth.credentials = [[HawkCredentials alloc] initWithHawkId:@"123456" withKey:@"2983d45yun89q" withAlgorithm:CryptoAlgorithmSHA256];
    auth.timestamp = [NSDate dateWithTimeIntervalSince1970:1365741469];

    NSString *expectedMac = @"h/Ff6XI1euObD78ZNflapvLKXGuaw1RiLI4Q6Q5sAbM=";
    NSString *actualMac = [auth timestampSkewHmac];

    XCTAssertEqualObjects(actualMac, expectedMac);
}

@end
