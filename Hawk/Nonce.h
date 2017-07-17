
#import <Foundation/Foundation.h>

extern const int DEFAULT_NONCE_LEN;

@interface Nonce : NSObject
+ (NSString *)generate;
+ (NSString *)generate:(NSUInteger)length;
@end
