
#import <XCTest/XCTest.h>
#import "Nonce.h"

@interface NonceTests : XCTestCase

@end

@implementation NonceTests

- (void)testNonceShouldGenerate {
        NSString *nonce = [Nonce generate];
        XCTAssertNotNil(nonce, @"Nonce was nil!");
        XCTAssertEqual(nonce.length, DEFAULT_NONCE_LEN,
                       @"Expected nonce length to be %d, got %@",
                       DEFAULT_NONCE_LEN,
                       @(nonce.length));
}

@end
