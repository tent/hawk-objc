//
//  NSString+Parser.m
//  Hawk
//
//  Created by Jesse Stuart on 8/7/13.
//  Copyright (c) 2013 Tent.is, LLC. All rights reserved.
//  Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.
//

#import "NSString+Parser.h"

@implementation NSString (Parser)

- (NSUInteger)firstIndexOf:(NSString *)substring
{
  NSRange range = [self rangeOfString:substring];
  if (range.location != NSNotFound) {
    return range.location;
  }
  return -1;
}

@end