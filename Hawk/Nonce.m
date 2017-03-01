
#import "Nonce.h"

const int DEFAULT_NONCE_LEN = 16;

@implementation Nonce

//TODO: This produces some fairly cryptic (no pun intended) nonces, e.g. 'EÒêµÇ[½\'
+ (NSString *)generate {
        return [self generate:DEFAULT_NONCE_LEN];
}

+ (NSString *)generate:(NSUInteger)length {
        uint8_t *bytes = malloc(sizeof(char) * (length + 1));
        if (bytes == NULL) {
                return nil;
        }
        int success = SecRandomCopyBytes(kSecRandomDefault, length, bytes);
        if (success != 0) {
                return nil;
        }
        bytes[length] = '\0';
        return [NSString stringWithCString:(const char *)bytes encoding:NSASCIIStringEncoding];
}
@end
