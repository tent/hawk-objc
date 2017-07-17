
#import "Nonce.h"

const int DEFAULT_NONCE_LEN = 16;

@implementation Nonce

+ (NSString *)generate {
        return [self generate:DEFAULT_NONCE_LEN];
}

+ (NSString *)generate:(NSUInteger)length {
    return [[[[NSProcessInfo processInfo] globallyUniqueString]
     stringByReplacingOccurrencesOfString:@"-" withString:@""]
     substringToIndex:length];
}
@end
