// The menu bar icon: a key and the number of secrets held, turning into an eye
// for a few seconds whenever secrets are read. menubar_darwin.go feeds it
// snapshots; the menu's actions go back through credlockMenubarAction.

#import <Cocoa/Cocoa.h>
#include "_cgo_export.h"
#include "menubar_darwin.h"

static const NSTimeInterval kEyeSeconds = 4;  // how long the eye stays after the last read
static const NSUInteger kLogItems = 20;       // uses shown in the menu

static NSStatusItem *item;
static NSMenu *menu;
static NSTimer *eyeTimer;
static NSUInteger heldCount;

static NSString *str(id d, NSString *key) {
  id v = [d isKindOfClass:[NSDictionary class]] ? d[key] : nil;
  return [v isKindOfClass:[NSString class]] ? v : @"";
}

static NSArray *list(id d, NSString *key) {
  id v = [d isKindOfClass:[NSDictionary class]] ? d[key] : nil;
  return [v isKindOfClass:[NSArray class]] ? v : @[];
}

static void sendAction(NSDictionary *action) {
  NSData *data = [NSJSONSerialization dataWithJSONObject:action options:0 error:nil];
  if (!data) {
    return;
  }
  NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  credlockMenubarAction((char *)s.UTF8String);
}

// CLTarget receives the menu's actions.
@interface CLTarget : NSObject
@end

@implementation CLTarget
- (void)forget:(NSMenuItem *)sender {
  NSDictionary *held = sender.representedObject;
  sendAction(@{@"op" : @"forget", @"account_id" : str(held, @"account_id"), @"ref" : str(held, @"ref")});
}
- (void)forgetAll:(id)sender {
  sendAction(@{@"op" : @"forget_all"});
}
- (void)stop:(id)sender {
  sendAction(@{@"op" : @"stop"});
}
@end

static CLTarget *target;

#pragma mark - The icon

static const CGFloat kIconHeight = 18;
static const CGFloat kDot = 7;  // the orange dot's diameter

static NSImage *keySymbol(void) {
  NSImage *img = [NSImage imageWithSystemSymbolName:@"key.fill" accessibilityDescription:nil];
  return [img imageWithSymbolConfiguration:[NSImageSymbolConfiguration configurationWithPointSize:13
                                                                                           weight:NSFontWeightSemibold]];
}

// drawTinted draws a symbol image in color, centred in r.
static void drawTinted(NSImage *img, NSColor *color, NSRect r) {
  if (!img) {
    return;
  }
  NSRect at = NSMakeRect(NSMidX(r) - img.size.width / 2, NSMidY(r) - img.size.height / 2, img.size.width,
                         img.size.height);
  // Draw the symbol's shape into its own image, then colour it, so the
  // colour doesn't spill onto what is already drawn.
  NSImage *tinted = [NSImage imageWithSize:img.size
                                   flipped:NO
                            drawingHandler:^BOOL(NSRect dst) {
                              [img drawInRect:dst];
                              [color set];
                              NSRectFillUsingOperation(dst, NSCompositingOperationSourceAtop);
                              return YES;
                            }];
  [tinted drawInRect:at];
}

// iconImage is the key and, while secrets are being read, an orange dot on its
// top right corner. The image is only as wide as the key plus half the dot,
// and the same in both states, so the number stays close and never moves.
static NSImage *iconImage(BOOL reading) {
  NSImage *key = keySymbol();
  CGFloat keyWidth = key ? key.size.width : 10;
  CGFloat width = ceil(keyWidth + kDot / 2);
  return [NSImage imageWithSize:NSMakeSize(width, kIconHeight)
                        flipped:NO
                 drawingHandler:^BOOL(NSRect r) {
                   drawTinted(key, NSColor.labelColor, NSMakeRect(0, 0, keyWidth, kIconHeight));
                   if (!reading) {
                     return YES;
                   }
                   NSRect dot = NSMakeRect(width - kDot, kIconHeight - kDot, kDot, kDot);
                   // A cut-out ring around the dot keeps it apart from the key.
                   [NSGraphicsContext currentContext].compositingOperation = NSCompositingOperationClear;
                   [[NSBezierPath bezierPathWithOvalInRect:NSInsetRect(dot, -1.5, -1.5)] fill];
                   [NSGraphicsContext currentContext].compositingOperation = NSCompositingOperationSourceOver;
                   [NSColor.systemOrangeColor setFill];
                   [[NSBezierPath bezierPathWithOvalInRect:dot] fill];
                   return YES;
                 }];
}

static void showIcon(BOOL eye) {
  NSString *what = eye ? @"credlock: secrets are being read" : @"credlock";
  NSImage *img = iconImage(eye);
  img.accessibilityDescription = what;
  item.button.image = img;
  item.button.title = [NSString stringWithFormat:@"%lu", (unsigned long)heldCount];
  item.button.toolTip = [NSString stringWithFormat:@"credlock: %lu secret%@ held%@", (unsigned long)heldCount,
                                                   heldCount == 1 ? @"" : @"s", eye ? @", being read now" : @""];
}

// showRead shows the eye, and keeps it up until kEyeSeconds after the last read.
static void showRead(void) {
  [eyeTimer invalidate];
  showIcon(YES);
  eyeTimer = [NSTimer timerWithTimeInterval:kEyeSeconds
                                    repeats:NO
                                      block:^(NSTimer *t) {
                                        eyeTimer = nil;
                                        showIcon(NO);
                                      }];
  // Common modes, so the eye goes back even while the menu is open.
  [[NSRunLoop mainRunLoop] addTimer:eyeTimer forMode:NSRunLoopCommonModes];
}

#pragma mark - The menu

static NSDictionary *secondary(CGFloat size) {
  return @{NSFontAttributeName : [NSFont menuFontOfSize:size], NSForegroundColorAttributeName : NSColor.secondaryLabelColor};
}

static NSMenuItem *heading(NSString *title) {
  if (@available(macOS 14.0, *)) {
    return [NSMenuItem sectionHeaderWithTitle:title];
  }
  NSMenuItem *m = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
  m.enabled = NO;
  return m;
}

static NSMenuItem *note(NSString *title) {
  NSMenuItem *m = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
  m.attributedTitle = [[NSAttributedString alloc] initWithString:title attributes:secondary(12)];
  m.enabled = NO;
  return m;
}

// logEntry is one use: when and what, then why, then which secrets.
static NSMenuItem *logEntry(NSDictionary *use) {
  NSMutableAttributedString *t = [NSMutableAttributedString new];
  NSString *when = [NSString stringWithFormat:@"%@  %@", str(use, @"at"), str(use, @"command")];
  [t appendAttributedString:[[NSAttributedString alloc]
                                initWithString:when
                                    attributes:@{NSFontAttributeName : [NSFont menuFontOfSize:13]}]];
  NSString *reason = str(use, @"reason");
  if (reason.length) {
    [t appendAttributedString:[[NSAttributedString alloc] initWithString:[@"\n" stringByAppendingString:reason]
                                                              attributes:secondary(12)]];
  }
  NSMutableArray *names = [NSMutableArray array];
  for (id n in list(use, @"names")) {
    if ([n isKindOfClass:[NSString class]]) {
      [names addObject:n];
    }
  }
  BOOL cached = [use[@"cached"] isKindOfClass:[NSNumber class]] && [use[@"cached"] boolValue];
  NSString *how = cached ? @"from the cache" : @"after you allowed it";
  NSString *which = [NSString stringWithFormat:@"\n%@ · %@", [names componentsJoinedByString:@", "], how];
  [t appendAttributedString:[[NSAttributedString alloc] initWithString:which attributes:secondary(11)]];
  NSMenuItem *m = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
  m.attributedTitle = t;
  m.enabled = YES;  // readable, not greyed; with no action a click just closes the menu
  return m;
}

// heldEntry is one secret: its name and time left, with its reference and a
// way to forget it in a submenu.
static NSMenuItem *heldEntry(NSDictionary *held) {
  NSMutableParagraphStyle *p = [NSMutableParagraphStyle new];
  p.tabStops = @[ [[NSTextTab alloc] initWithTextAlignment:NSTextAlignmentRight location:300 options:@{}] ];
  NSMutableAttributedString *t = [[NSMutableAttributedString alloc]
      initWithString:str(held, @"name")
          attributes:@{NSFontAttributeName : [NSFont monospacedSystemFontOfSize:12.5 weight:NSFontWeightMedium],
                       NSParagraphStyleAttributeName : p}];
  [t appendAttributedString:[[NSAttributedString alloc]
                                initWithString:[@"\t" stringByAppendingString:str(held, @"left")]
                                    attributes:@{NSFontAttributeName : [NSFont menuFontOfSize:12],
                                                 NSForegroundColorAttributeName : NSColor.secondaryLabelColor,
                                                 NSParagraphStyleAttributeName : p}]];
  NSMenuItem *m = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
  m.attributedTitle = t;
  NSMenu *sub = [NSMenu new];
  sub.autoenablesItems = NO;
  [sub addItem:note(str(held, @"ref"))];
  [sub addItem:[NSMenuItem separatorItem]];
  NSMenuItem *forget = [[NSMenuItem alloc] initWithTitle:[@"Forget " stringByAppendingString:str(held, @"name")]
                                                  action:@selector(forget:)
                                           keyEquivalent:@""];
  forget.target = target;
  forget.representedObject = held;
  [sub addItem:forget];
  m.submenu = sub;
  return m;
}

static void rebuild(NSArray *held, NSArray *uses) {
  [menu removeAllItems];
  NSString *count = [NSString stringWithFormat:@"credlock is holding %lu secret%@", (unsigned long)held.count,
                                               held.count == 1 ? @"" : @"s"];
  [menu addItem:note(count)];

  [menu addItem:[NSMenuItem separatorItem]];
  [menu addItem:heading(@"Access log")];
  if (uses.count == 0) {
    [menu addItem:note(@"Nothing read yet")];
  }
  NSUInteger shown = 0;
  for (id use in uses) {
    if (shown++ == kLogItems) {
      break;
    }
    [menu addItem:logEntry(use)];
  }

  [menu addItem:[NSMenuItem separatorItem]];
  [menu addItem:heading(@"Held secrets")];
  NSString *account = nil;
  for (id h in held) {
    if (![str(h, @"account") isEqualToString:account]) {
      account = str(h, @"account");
      [menu addItem:note(account)];
    }
    [menu addItem:heldEntry(h)];
  }

  [menu addItem:[NSMenuItem separatorItem]];
  NSMenuItem *all = [[NSMenuItem alloc] initWithTitle:@"Forget all" action:@selector(forgetAll:) keyEquivalent:@""];
  all.target = target;
  [menu addItem:all];
  NSMenuItem *stop = [[NSMenuItem alloc] initWithTitle:@"Stop credlock" action:@selector(stop:) keyEquivalent:@""];
  stop.target = target;
  [menu addItem:stop];
}

static void apply(NSDictionary *v) {
  NSArray *held = list(v, @"held");
  heldCount = held.count;
  rebuild(held, list(v, @"uses"));
  item.visible = heldCount > 0;
  BOOL isRead = [v[@"read"] isKindOfClass:[NSNumber class]] && [v[@"read"] boolValue];
  if (isRead && heldCount > 0) {
    showRead();
  } else {
    showIcon(eyeTimer != nil);
  }
}

#pragma mark - Entry points

void credlock_menubar_run(void) {
  @autoreleasepool {
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    target = [CLTarget new];
    menu = [NSMenu new];
    menu.autoenablesItems = NO;
    item = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    item.button.imagePosition = NSImageLeft;
    item.button.imageHugsTitle = YES;
    item.button.font = [NSFont monospacedDigitSystemFontOfSize:[NSFont systemFontSize] weight:NSFontWeightRegular];
    item.menu = menu;
    item.visible = NO;
    [NSApp run];
  }
}

void credlock_menubar_update(const char *json) {
  NSData *data = [NSData dataWithBytes:json length:strlen(json)];
  dispatch_async(dispatch_get_main_queue(), ^{
    id v = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if ([v isKindOfClass:[NSDictionary class]]) {
      apply(v);
    }
  });
}

int credlock_menubar_icon_snapshot(const char *path, int dark) {
  @autoreleasepool {
    [NSApplication sharedApplication];
    NSAppearance *look = [NSAppearance appearanceNamed:dark ? NSAppearanceNameDarkAqua : NSAppearanceNameAqua];
    __block NSData *png = nil;
    [look performAsCurrentDrawingAppearance:^{
      NSSize strip = NSMakeSize(130, 24);
      CGFloat scale = 4;
      NSBitmapImageRep *rep = [[NSBitmapImageRep alloc] initWithBitmapDataPlanes:NULL
                                                                      pixelsWide:(NSInteger)(strip.width * scale)
                                                                      pixelsHigh:(NSInteger)(strip.height * scale)
                                                                   bitsPerSample:8
                                                                 samplesPerPixel:4
                                                                        hasAlpha:YES
                                                                        isPlanar:NO
                                                                  colorSpaceName:NSCalibratedRGBColorSpace
                                                                     bytesPerRow:0
                                                                    bitsPerPixel:0];
      rep.size = strip;
      [NSGraphicsContext saveGraphicsState];
      [NSGraphicsContext setCurrentContext:[NSGraphicsContext graphicsContextWithBitmapImageRep:rep]];
      [[NSColor colorWithWhite:dark ? 0.17 : 0.93 alpha:1] setFill];
      NSRectFill(NSMakeRect(0, 0, strip.width, strip.height));
      NSDictionary *font = @{
        NSFontAttributeName : [NSFont monospacedDigitSystemFontOfSize:13 weight:NSFontWeightRegular],
        NSForegroundColorAttributeName : NSColor.labelColor
      };
      for (int i = 0; i < 2; i++) {
        CGFloat x = 12 + i * 62;
        NSImage *img = iconImage(i == 1);
        [img drawInRect:NSMakeRect(x, 3, img.size.width, img.size.height)];
        // About the gap AppKit leaves when the image hugs the title.
        [@"4" drawAtPoint:NSMakePoint(x + img.size.width + 3, 4) withAttributes:font];
      }
      [NSGraphicsContext restoreGraphicsState];
      png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    }];
    return png && [png writeToFile:[NSString stringWithUTF8String:path] atomically:YES] ? 0 : -1;
  }
}

void credlock_menubar_quit(void) {
  dispatch_async(dispatch_get_main_queue(), ^{
    [NSApp terminate:nil];
  });
}
