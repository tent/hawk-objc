//
//  NSString+Parser.m
//  Hawk
//
//  Created by Jesse Stuart on 8/7/13.
//  Copyright (c) 2013 Tent. All rights reserved.
//

#import "NSString+Parser.h"

@implementation NSString (Parser)

- (NSUInteger *)firstIndexOf:(NSString *)substring
{
    for (int i=0; i<self.length; i++) {
        if ([[[self substringFromIndex:i] substringToIndex:substring.length] isEqualToString:substring]) {
            return (NSUInteger *)[[NSNumber numberWithInt:i] integerValue];
        }
    }

    return nil;
}

@end
