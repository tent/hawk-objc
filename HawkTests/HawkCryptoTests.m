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
@property (nonatomic, strong) HawkAuthBuilder *builder;
@property (nonatomic, strong) HawkCredentials *creds;
@property (nonatomic, strong) HawkCredentials *emptyCreds;
@end

@implementation HawkCryptoTests

- (void)setUp {
    [super setUp];
        self.creds = [HawkCredentials withKeyId:@"123456"
                                            key:@"2983d45yun89q"
                                      algorithm:kCryptoAlgorithmSHA1];
        
        self.emptyCreds =  [HawkCredentials withKeyId:@""
                                                  key:@""
                                            algorithm:kCryptoAlgorithmSHA1];
        
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testPayloadHashWithChangingAlgorithms {
        self.builder = [[[HawkAuthBuilder withCredentials:self.creds]
                         usingContentType:kContentTypeEmpty]
                        withPayload:@"something to write about"];
        
        HawkAuth *sha1Auth = [self.builder build];

        NSString *expectedHash;
        NSString *actualHash;

        // SHA1
        expectedHash = @"bsvY3IfUllw6V5rvk4tStEvpBhE=";
        actualHash = [sha1Auth payloadHash];

        XCTAssertEqualObjects(actualHash, expectedHash);

        // SHA256
        HawkAuth *sha256Auth = [[self.builder switchAlgorithm:kCryptoAlgorithmSHA256] build];
        expectedHash = @"LjRmtkSKTW0ObTUyZ7N+vjClKd//KTTdfhF1M4XCuEM=";
        actualHash = [sha256Auth payloadHash];

        XCTAssertEqualObjects(actualHash, expectedHash);
}

- (void)testPayloadHashWithComplexContentType {
        self.builder = [[[HawkAuthBuilder withCredentials:self.emptyCreds]
                         withContentType:@"text/plain; type=\"something\""]
                        withPayload:@"Something to write about"];

    NSString *expectedHash;
    NSString *actualHash;

    expectedHash = @"s3exeO2OBG5Q198BIN1HvEsbVB4=";
    actualHash = [[self.builder build] payloadHash];

    XCTAssertEqualObjects(actualHash, expectedHash);

    // SHA256
        [self.builder switchAlgorithm:kCryptoAlgorithmSHA256];
    expectedHash = @"RBzsyF5kNxkvMWvOKj90ULW1LHqOwqRo1sAEjjUkPuo=";
    actualHash = [[self.builder build] payloadHash];

    XCTAssertEqualObjects(actualHash, expectedHash);
}

- (void)testPayloadHashWithWhiteSpaceInContentType {
    // Common setup
    self.builder = [[[HawkAuthBuilder withCredentials:self.emptyCreds]
                     withContentType:@" text/plain ; type=\"something\""]
                    withPayload:@"Something to write about"];

    NSString *expectedHash;
    NSString *actualHash;

    // SHA1
    expectedHash = @"s3exeO2OBG5Q198BIN1HvEsbVB4=";
    actualHash = [[self.builder build] payloadHash];

    XCTAssertEqualObjects(actualHash, expectedHash);

    // SHA256
        [self.builder switchAlgorithm:kCryptoAlgorithmSHA256];
    expectedHash = @"RBzsyF5kNxkvMWvOKj90ULW1LHqOwqRo1sAEjjUkPuo=";
    actualHash = [[self.builder build] payloadHash];

    XCTAssertEqualObjects(actualHash, expectedHash);
}

- (void)testBewit {
        self.builder = [[[[[[[[HawkAuthBuilder withCredentials:self.creds]
                              switchAlgorithm:kCryptoAlgorithmSHA256]
                             withTimestamp:[NSDate dateWithTimeIntervalSince1970:4519311458]]
                            usingGET]
                           withHost:@"example.com"]
                          withPort:@(80)]
                         withResourcePath:@"/resource/4?a=1&b=2"]
                        withExt:@"some-app-data"];

    NSString *expectedBewit = @"MTIzNDU2XDQ1MTkzMTE0NThcYkkwanFlS1prUHE0V1hRMmkxK0NrQ2lOanZEc3BSVkNGajlmbElqMXphWT1cc29tZS1hcHAtZGF0YQ";
    NSString *actualBewit = [[self.builder build] bewit];

    XCTAssertEqualObjects(actualBewit, expectedBewit);
}

- (void)testMac {
    self.builder = [[[[[[[[[[HawkAuthBuilder withCredentials:self.creds]
                            withTimestamp:[NSDate dateWithTimeIntervalSince1970:1353809207]]
                           usingContentType:kContentTypeEmpty]
                          usingPOST]
                         withHost:@"example.net"]
                        withPort:@(80)]
                       withResourcePath:@"/somewhere/over/the/rainbow"]
                      withExt:@"Bazinga!"]
                     withPayload:@"something to write about"]
                    withNonce:@"Ygvqdz"];

    NSString *expectedMac;
    NSString *actualMac;

    // SHA1
    expectedMac = @"qbf1ZPG/r/e06F4ht+T77LXi5vw=";
    actualMac = [[self.builder build] hmacWithType:kHawkAuthTypeHeader];

    XCTAssertEqualObjects(actualMac, expectedMac);

    // SHA256
        [self.builder switchAlgorithm:kCryptoAlgorithmSHA256];
    expectedMac = @"dh5kEkotNusOuHPolRYUhvy2vlhJybTC2pqBdUQk5z0=";
    actualMac = [[self.builder build] hmacWithType:kHawkAuthTypeHeader];

    XCTAssertEqualObjects(actualMac, expectedMac);
}

- (void)testTimestampSkewMac {
    self.builder = [[[HawkAuthBuilder withCredentials:self.creds]
        switchAlgorithm:kCryptoAlgorithmSHA256]
                    withTimestamp:[NSDate dateWithTimeIntervalSince1970:1365741469]];

    NSString *expectedMac = @"h/Ff6XI1euObD78ZNflapvLKXGuaw1RiLI4Q6Q5sAbM=";
    NSString *actualMac = [[self.builder build] timestampSkewHmac];

    XCTAssertEqualObjects(actualMac, expectedMac);
}

@end
