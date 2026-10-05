// The approval window: native AppKit, laid out in code. window_darwin.go
// starts it, and everything it shows arrives already cleaned, as View JSON.
//
// Deny is the default. Esc denies; Return does nothing, so typing that lands
// on the window can't approve anything. Allow takes a mouse click, is dimmed
// and ignores clicks for its first second on screen (so a click meant for
// another window can't land on it), and ignores the click that merely brings
// the window forward.

#import <Cocoa/Cocoa.h>
#include "window_darwin.h"

// Layout, in points. Generous on purpose: each block should read on its own.
static const CGFloat kWidth = 620;              // the window's width
static const CGFloat kMargin = 32;              // window edge to content
static const CGFloat kInner = kWidth - 2 * kMargin;
static const CGFloat kSection = 24;             // between the main blocks
static const CGFloat kCardPad = 20;             // card edge to its content
static const CGFloat kCardInner = kInner - 2 * kCardPad;
static const CGFloat kIconGap = 14;             // icon to its text
static const CGFloat kColumnGap = 24;           // between side-by-side details
static const CGFloat kLabelGap = 4;             // a detail's title to its value
static const int kScrollAfter = 6;              // more secrets than this scroll

enum { kAllow = 1001, kDeny, kTimedOut };

#pragma mark - Building blocks

// CLTile is a rounded rectangle that draws its colours at draw time, so they
// follow light and dark mode.
@interface CLTile : NSView
@property(strong) NSColor *fill;
@property(strong) NSColor *border;
@property CGFloat radius;
@end

@implementation CLTile
- (BOOL)isFlipped {
  return YES;
}
- (void)drawRect:(NSRect)dirty {
  NSBezierPath *p = [NSBezierPath bezierPathWithRoundedRect:NSInsetRect(self.bounds, 0.5, 0.5)
                                                    xRadius:self.radius
                                                    yRadius:self.radius];
  if (self.fill) {
    [self.fill setFill];
    [p fill];
  }
  if (self.border) {
    [self.border setStroke];
    p.lineWidth = 1;
    [p stroke];
  }
}
@end

// raised is the fill for things that sit on the window: white in light mode, a
// faint lift in dark mode (where controlBackgroundColor would be a dark hole).
static NSColor *raised(void) {
  return [NSColor colorWithName:nil
                dynamicProvider:^NSColor *(NSAppearance *a) {
                  BOOL dark = [[a bestMatchFromAppearancesWithNames:@[ NSAppearanceNameAqua, NSAppearanceNameDarkAqua ]]
                      isEqualToString:NSAppearanceNameDarkAqua];
                  return dark ? [NSColor colorWithWhite:1 alpha:0.09] : NSColor.whiteColor;
                }];
}

static CLTile *tile(NSColor *fill, NSColor *border, CGFloat radius) {
  CLTile *t = [[CLTile alloc] initWithFrame:NSZeroRect];
  t.fill = fill;
  t.border = border;
  t.radius = radius;
  t.translatesAutoresizingMaskIntoConstraints = NO;
  return t;
}

static void pin(NSView *v, NSView *to, CGFloat inset) {
  v.translatesAutoresizingMaskIntoConstraints = NO;
  [NSLayoutConstraint activateConstraints:@[
    [v.leadingAnchor constraintEqualToAnchor:to.leadingAnchor constant:inset],
    [v.trailingAnchor constraintEqualToAnchor:to.trailingAnchor constant:-inset],
    [v.topAnchor constraintEqualToAnchor:to.topAnchor constant:inset],
    [v.bottomAnchor constraintEqualToAnchor:to.bottomAnchor constant:-inset],
  ]];
}

static void fixWidth(NSView *v, CGFloat width) {
  v.translatesAutoresizingMaskIntoConstraints = NO;
  [v.widthAnchor constraintEqualToConstant:width].active = YES;
}

static NSFont *sys(CGFloat size, NSFontWeight weight) {
  return [NSFont systemFontOfSize:size weight:weight];
}

static NSFont *mono(CGFloat size, NSFontWeight weight) {
  return [NSFont monospacedSystemFontOfSize:size weight:weight];
}

// text is a label that wraps at width.
static NSTextField *text(NSString *s, NSFont *font, NSColor *color, CGFloat width) {
  NSTextField *l = [NSTextField wrappingLabelWithString:s];
  l.font = font;
  l.textColor = color;
  l.selectable = NO;
  l.preferredMaxLayoutWidth = width;
  fixWidth(l, width);
  return l;
}

// line is a label that doesn't wrap.
static NSTextField *line(NSString *s, NSFont *font, NSColor *color) {
  NSTextField *l = [NSTextField labelWithString:s];
  l.font = font;
  l.textColor = color;
  l.translatesAutoresizingMaskIntoConstraints = NO;
  return l;
}

static NSImageView *symbol(NSString *name, CGFloat size, NSColor *color) {
  NSImage *img = [NSImage imageWithSystemSymbolName:name accessibilityDescription:nil];
  NSImageSymbolConfiguration *cfg =
      [NSImageSymbolConfiguration configurationWithPointSize:size weight:NSFontWeightMedium];
  img = img ? [img imageWithSymbolConfiguration:cfg] : [[NSImage alloc] initWithSize:NSMakeSize(size, size)];
  NSImageView *v = [NSImageView imageViewWithImage:img];
  v.contentTintColor = color;
  v.translatesAutoresizingMaskIntoConstraints = NO;
  return v;
}

// badge is an icon on a tile: tinted and round in the cards, plain and square
// beside the details.
static NSView *badge(NSString *name, CGFloat size, NSColor *tint, BOOL round) {
  CLTile *t = tint ? tile([tint colorWithAlphaComponent:0.16], nil, round ? size / 2 : 9)
                   : tile(raised(), NSColor.separatorColor, 9);
  [NSLayoutConstraint activateConstraints:@[
    [t.widthAnchor constraintEqualToConstant:size],
    [t.heightAnchor constraintEqualToConstant:size],
  ]];
  NSImageView *icon = symbol(name, size * 0.44, tint ? tint : NSColor.secondaryLabelColor);
  [t addSubview:icon];
  [NSLayoutConstraint activateConstraints:@[
    [icon.centerXAnchor constraintEqualToAnchor:t.centerXAnchor],
    [icon.centerYAnchor constraintEqualToAnchor:t.centerYAnchor],
  ]];
  return t;
}

static NSStackView *vstack(NSArray<NSView *> *views, CGFloat spacing) {
  NSStackView *s = [NSStackView stackViewWithViews:views];
  s.orientation = NSUserInterfaceLayoutOrientationVertical;
  s.alignment = NSLayoutAttributeLeading;
  s.spacing = spacing;
  s.translatesAutoresizingMaskIntoConstraints = NO;
  return s;
}

static NSStackView *hstack(NSArray<NSView *> *views, CGFloat spacing, NSLayoutAttribute align) {
  NSStackView *s = [NSStackView stackViewWithViews:views];
  s.orientation = NSUserInterfaceLayoutOrientationHorizontal;
  s.alignment = align;
  s.spacing = spacing;
  s.translatesAutoresizingMaskIntoConstraints = NO;
  return s;
}

// card is a tinted, rounded panel around content.
static NSView *card(NSColor *tint, NSView *content) {
  CLTile *t = tile([tint colorWithAlphaComponent:0.07], [tint colorWithAlphaComponent:0.28], 14);
  [t addSubview:content];
  pin(content, t, kCardPad);
  fixWidth(t, kInner);
  return t;
}

// detail is one fact about the request: an icon, a small title, the value.
static NSView *detail(NSString *icon, NSString *title, NSString *value, NSFont *font, CGFloat width) {
  CGFloat words = width - 34 - kIconGap;
  NSStackView *s = vstack(@[
    text(title, sys(12, NSFontWeightSemibold), NSColor.secondaryLabelColor, words),
    text(value, font, NSColor.labelColor, words),
  ],
                          kLabelGap);
  return hstack(@[ badge(icon, 34, nil, NO), s ], kIconGap, NSLayoutAttributeTop);
}

static NSView *secret(NSString *name, NSString *ref, CGFloat width) {
  CGFloat words = width - 30 - kIconGap;
  NSStackView *s = vstack(@[
    text(name, mono(12.5, NSFontWeightSemibold), NSColor.labelColor, words),
    text(ref, mono(11.5, NSFontWeightRegular), NSColor.secondaryLabelColor, words),
  ],
                          3);
  return hstack(@[ badge(@"key.fill", 30, NSColor.systemGreenColor, YES), s ], kIconGap,
                NSLayoutAttributeCenterY);
}

// CLFlipped lays out top down, for the document view of a scrolling list.
@interface CLFlipped : NSView
@end
@implementation CLFlipped
- (BOOL)isFlipped {
  return YES;
}
@end

#pragma mark - Buttons

// CLButton is a large rounded button. It is a plain view rather than an
// NSButton so it can't be focused from the keyboard, and so that Allow can
// stay out of the accessibility tree: nothing can press it but a click.
@interface CLButton : CLTile
@property(copy) void (^onPress)(void);
@property(nonatomic) BOOL armed;
@property BOOL primary;
@property BOOL exposed;  // offered to accessibility as a button
@property BOOL pressed;
@property BOOL hovering;
@property(copy) NSString *title;
@end

@implementation CLButton

- (instancetype)initWithTitle:(NSString *)title
                         hint:(NSString *)hint
                       symbol:(NSString *)name
                      primary:(BOOL)primary
                        width:(CGFloat)width {
  self = [super initWithFrame:NSZeroRect];
  self.title = title;
  self.primary = primary;
  self.radius = 12;
  self.translatesAutoresizingMaskIntoConstraints = NO;
  [NSLayoutConstraint activateConstraints:@[
    [self.widthAnchor constraintEqualToConstant:width],
    [self.heightAnchor constraintEqualToConstant:58],
  ]];
  NSColor *fg = primary ? NSColor.whiteColor : NSColor.labelColor;
  NSColor *dim = primary ? [NSColor.whiteColor colorWithAlphaComponent:0.8] : NSColor.secondaryLabelColor;
  NSMutableArray *words = [NSMutableArray arrayWithObject:line(title, sys(15, NSFontWeightSemibold), fg)];
  if (hint.length) {
    [words addObject:line(hint, sys(11.5, NSFontWeightMedium), dim)];
  }
  NSStackView *content =
      hstack(@[ symbol(name, 17, fg), vstack(words, 1) ], 10, NSLayoutAttributeCenterY);
  [self addSubview:content];
  [NSLayoutConstraint activateConstraints:@[
    [content.centerXAnchor constraintEqualToAnchor:self.centerXAnchor],
    [content.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],
  ]];
  self.armed = YES;
  return self;
}

- (void)setArmed:(BOOL)armed {
  _armed = armed;
  self.alphaValue = armed ? 1 : 0.4;
}

- (void)drawRect:(NSRect)dirty {
  NSColor *green = [NSColor.systemGreenColor blendedColorWithFraction:0.12 ofColor:NSColor.blackColor];
  NSColor *base = self.primary ? (green ?: NSColor.systemGreenColor) : raised();
  NSColor *shade = self.primary ? NSColor.blackColor : NSColor.labelColor;
  CGFloat f = self.pressed ? 0.18 : (self.hovering && self.armed ? 0.07 : 0);
  self.fill = f > 0 ? ([base blendedColorWithFraction:f ofColor:shade] ?: base) : base;
  self.border = self.primary ? nil : NSColor.separatorColor;
  [super drawRect:dirty];
}

// Clicks on the labels inside belong to the button.
- (NSView *)hitTest:(NSPoint)p {
  return [super hitTest:p] ? self : nil;
}

// The click that brings the window forward is not a press.
- (BOOL)acceptsFirstMouse:(NSEvent *)event {
  return NO;
}

- (void)updateTrackingAreas {
  [super updateTrackingAreas];
  for (NSTrackingArea *a in self.trackingAreas) {
    [self removeTrackingArea:a];
  }
  [self addTrackingArea:[[NSTrackingArea alloc]
                            initWithRect:NSZeroRect
                                 options:NSTrackingMouseEnteredAndExited | NSTrackingActiveAlways |
                                         NSTrackingInVisibleRect
                                   owner:self
                                userInfo:nil]];
}

- (void)mouseEntered:(NSEvent *)event {
  self.hovering = YES;
  [self setNeedsDisplay:YES];
}

- (void)mouseExited:(NSEvent *)event {
  self.hovering = NO;
  [self setNeedsDisplay:YES];
}

- (void)mouseDown:(NSEvent *)event {
  if (!self.armed) {
    return;
  }
  BOOL inside = YES;
  self.pressed = YES;
  [self display];
  for (;;) {
    NSEvent *next = [self.window nextEventMatchingMask:NSEventMaskLeftMouseUp | NSEventMaskLeftMouseDragged];
    inside = NSPointInRect([self convertPoint:next.locationInWindow fromView:nil], self.bounds);
    if (inside != self.pressed) {
      self.pressed = inside;
      [self display];
    }
    if (next.type == NSEventTypeLeftMouseUp) {
      break;
    }
  }
  self.pressed = NO;
  [self display];
  if (inside && self.armed && self.onPress) {
    self.onPress();
  }
}

- (BOOL)isAccessibilityElement {
  return self.exposed;
}
- (NSAccessibilityRole)accessibilityRole {
  return self.exposed ? NSAccessibilityButtonRole : NSAccessibilityUnknownRole;
}
- (NSString *)accessibilityLabel {
  return self.exposed ? self.title : nil;
}
- (NSArray *)accessibilityChildren {
  return self.exposed ? [super accessibilityChildren] : @[];
}
- (BOOL)accessibilityPerformPress {
  if (!self.exposed || !self.armed || !self.onPress) {
    return NO;
  }
  self.onPress();
  return YES;
}

@end

#pragma mark - The window

// CLPanel denies on Esc and ignores every other key, Return included.
@interface CLPanel : NSPanel
@property(copy) void (^onEscape)(void);
@end

@implementation CLPanel
- (BOOL)canBecomeKeyWindow {
  return YES;
}
- (void)cancelOperation:(id)sender {
  if (self.onEscape) {
    self.onEscape();
  }
}
- (void)keyDown:(NSEvent *)event {
  if (event.keyCode == 53 && self.onEscape) {  // Esc
    self.onEscape();
  }
}
@end

@interface CLWindow : NSObject
@property(strong) CLPanel *panel;
@property(strong) CLButton *allow;
@property(strong) CLButton *deny;
@property(strong) NSTextField *countdown;
@end
@implementation CLWindow
@end

static NSString *str(NSDictionary *d, NSString *key) {
  id v = [d isKindOfClass:[NSDictionary class]] ? d[key] : nil;
  return [v isKindOfClass:[NSString class]] ? v : @"";
}

static NSString *remaining(int seconds) {
  return [NSString stringWithFormat:@"Counts as Deny in %d:%02d", seconds / 60, seconds % 60];
}

static NSDictionary *parse(const char *json) {
  NSData *data = [NSData dataWithBytes:json length:strlen(json)];
  id v = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
  return [v isKindOfClass:[NSDictionary class]] ? v : nil;
}

static CLWindow *build(NSDictionary *v, int timeout) {
  CLWindow *w = [CLWindow new];

  // Who is asking.
  NSImageView *shield = symbol(@"lock.shield.fill", 30, NSColor.systemGreenColor);
  NSView *header = hstack(@[
    shield,
    vstack(@[
      line(str(v, @"title"), sys(20, NSFontWeightBold), NSColor.labelColor),
      line(str(v, @"subtitle"), sys(12, NSFontWeightMedium), NSColor.secondaryLabelColor),
    ],
           2),
  ],
                          14, NSLayoutAttributeCenterY);

  NSTextField *question = text(str(v, @"question"), sys(17, NSFontWeightSemibold), NSColor.labelColor, kInner);

  // From another machine: said first, in a card nothing a requester sends
  // can produce.
  NSView *origin = nil;
  if (str(v, @"origin").length) {
    // Blue for a paired machine, purple for a first pairing.
    BOOL pairing = [str(v, @"origin_tone") isEqualToString:@"pair"];
    NSColor *colour = pairing ? NSColor.systemPurpleColor : NSColor.systemBlueColor;
    NSString *icon = pairing ? @"link" : @"network";
    CGFloat words = kCardInner - 42 - kIconGap;
    NSView *about = hstack(@[
      badge(icon, 42, colour, YES),
      vstack(@[
        text(str(v, @"origin_title"), sys(15, NSFontWeightSemibold), NSColor.labelColor, words),
        text(str(v, @"origin_note"), sys(12, NSFontWeightRegular), NSColor.secondaryLabelColor, words),
      ],
             kLabelGap),
    ],
                           kIconGap, NSLayoutAttributeCenterY);
    NSString *code = str(v, @"code");
    if (code.length) {
      // The pairing code, large enough that it can't be missed: "7 9 4 3".
      NSMutableArray *digits = [NSMutableArray array];
      for (NSUInteger i = 0; i < code.length; i++) {
        [digits addObject:[code substringWithRange:NSMakeRange(i, 1)]];
      }
      NSView *indent = [[NSView alloc] initWithFrame:NSZeroRect];
      fixWidth(indent, 42 + kIconGap - 8);
      NSView *codeRow = hstack(@[
        indent,
        line([digits componentsJoinedByString:@" "], mono(34, NSFontWeightBold), colour),
        text(str(v, @"code_note"), sys(12, NSFontWeightMedium), NSColor.secondaryLabelColor, words - 170),
      ],
                               18, NSLayoutAttributeCenterY);
      about = vstack(@[ about, codeRow ], 12);
    }
    origin = card(colour, about);
  }

  // Why.
  CGFloat reasonWords = kCardInner - 42 - kIconGap;
  NSView *reason = card(NSColor.systemOrangeColor, hstack(@[
                          badge(@"text.bubble.fill", 42, NSColor.systemOrangeColor, YES),
                          vstack(@[
                            text(@"Reason", sys(12, NSFontWeightSemibold), NSColor.systemOrangeColor, reasonWords),
                            text(str(v, @"reason"), sys(15, NSFontWeightSemibold), NSColor.labelColor, reasonWords),
                          ],
                                 kLabelGap),
                        ],
                                                               kIconGap, NSLayoutAttributeCenterY));

  // What, where and for how long.
  CGFloat half = (kInner - kColumnGap) / 2;
  NSFont *code = mono(12, NSFontWeightRegular);
  NSFont *plain = sys(12.5, NSFontWeightRegular);
  NSView *details = vstack(@[
    detail(@"terminal", @"Command", str(v, @"command"), code, kInner),
    hstack(@[
      detail(@"folder", @"Directory", str(v, @"directory"), code, half),
      detail(@"cpu", @"Requested by", str(v, @"requester"), code, half),
    ],
           kColumnGap, NSLayoutAttributeTop),
    hstack(@[
      detail(@"person.crop.circle", @"1Password account", str(v, @"account"), plain, half),
      detail(@"clock", @"Approval lasts", str(v, @"lifetime"), plain, half),
    ],
           kColumnGap, NSLayoutAttributeTop),
  ],
                           18);

  // Which secrets.
  NSArray *list = [v[@"secrets"] isKindOfClass:[NSArray class]] ? v[@"secrets"] : @[];
  BOOL scrolls = list.count > kScrollAfter;
  CGFloat rowWidth = scrolls ? kCardInner - 18 : kCardInner;
  NSMutableArray *rows = [NSMutableArray array];
  for (id s in list) {
    [rows addObject:secret(str(s, @"name"), str(s, @"ref"), rowWidth)];
  }
  NSStackView *rowStack = vstack(rows, 14);
  NSView *listView = rowStack;
  NSString *secretsTitle = str(v, @"secrets_title");
  if (scrolls) {
    secretsTitle = [secretsTitle stringByAppendingString:@" · scroll to see them all"];
    CLFlipped *doc = [[CLFlipped alloc] initWithFrame:NSZeroRect];
    [doc addSubview:rowStack];
    pin(rowStack, doc, 0);
    NSScrollView *sv = [[NSScrollView alloc] initWithFrame:NSZeroRect];
    sv.hasVerticalScroller = YES;
    sv.drawsBackground = NO;
    sv.borderType = NSNoBorder;
    sv.documentView = doc;
    doc.translatesAutoresizingMaskIntoConstraints = NO;
    [NSLayoutConstraint activateConstraints:@[
      [doc.leadingAnchor constraintEqualToAnchor:sv.contentView.leadingAnchor],
      [doc.topAnchor constraintEqualToAnchor:sv.contentView.topAnchor],
      [doc.widthAnchor constraintEqualToConstant:rowWidth],
    ]];
    fixWidth(sv, kCardInner);
    [sv.heightAnchor constraintEqualToConstant:kScrollAfter * 44 + (kScrollAfter - 1) * 14].active = YES;
    listView = sv;
  }
  NSMutableArray *secretsParts = [NSMutableArray arrayWithObjects:
      text(secretsTitle, sys(13, NSFontWeightSemibold), NSColor.systemGreenColor, kCardInner), listView, nil];
  if (str(v, @"approved").length) {
    [secretsParts addObject:text(str(v, @"approved"), sys(12, NSFontWeightRegular), NSColor.secondaryLabelColor,
                                 kCardInner)];
  }
  // A pairing on its own has no secrets: no card for them.
  NSView *secrets = list.count ? card(NSColor.systemGreenColor, vstack(secretsParts, 16)) : nil;

  // The answer.
  CGFloat buttonWidth = (kInner - 16) / 2;
  w.deny = [[CLButton alloc] initWithTitle:@"Deny" hint:@"Esc" symbol:@"xmark" primary:NO width:buttonWidth];
  w.deny.exposed = YES;
  w.allow = [[CLButton alloc] initWithTitle:@"Allow"
                                       hint:@"Click"
                                     symbol:@"checkmark.shield.fill"
                                    primary:YES
                                      width:buttonWidth];
  NSView *buttons = hstack(@[ w.deny, w.allow ], 16, NSLayoutAttributeCenterY);

  w.countdown = line(remaining(timeout), [NSFont monospacedDigitSystemFontOfSize:11.5 weight:NSFontWeightRegular],
                     NSColor.secondaryLabelColor);
  NSStackView *footer = hstack(@[
    symbol(@"lock.fill", 11, NSColor.tertiaryLabelColor),
    text(str(v, @"footer"), sys(11.5, NSFontWeightRegular), NSColor.secondaryLabelColor, kInner - 170),
  ],
                               8, NSLayoutAttributeCenterY);
  [footer addView:w.countdown inGravity:NSStackViewGravityTrailing];
  fixWidth(footer, kInner);

  NSMutableArray *blocks = [NSMutableArray arrayWithObject:header];
  if (origin) {
    [blocks addObject:origin];
  }
  [blocks addObjectsFromArray:@[ question, reason, details ]];
  if (secrets) {
    [blocks addObject:secrets];
  }
  [blocks addObjectsFromArray:@[ buttons, footer ]];
  NSStackView *root = vstack(blocks, kSection);
  [root setCustomSpacing:20 afterView:header];
  [root setCustomSpacing:18 afterView:question];
  [root setCustomSpacing:28 afterView:secrets ?: details];
  [root setCustomSpacing:16 afterView:buttons];
  root.edgeInsets = NSEdgeInsetsMake(kMargin + 4, kMargin, kMargin - 6, kMargin);
  fixWidth(root, kWidth);

  CLTile *background = tile(NSColor.windowBackgroundColor, nil, 0);
  [background addSubview:root];
  pin(root, background, 0);
  NSSize size = background.fittingSize;

  CLPanel *panel = [[CLPanel alloc] initWithContentRect:NSMakeRect(0, 0, size.width, size.height)
                                              styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskFullSizeContentView
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
  panel.title = @"credlock";
  panel.titleVisibility = NSWindowTitleHidden;
  panel.titlebarAppearsTransparent = YES;
  panel.movableByWindowBackground = YES;
  panel.releasedWhenClosed = NO;
  for (NSWindowButton b = NSWindowCloseButton; b <= NSWindowZoomButton; b++) {
    [[panel standardWindowButton:b] setHidden:YES];
  }
  panel.contentView = background;
  w.panel = panel;
  return w;
}

static int timeoutOf(NSDictionary *v) {
  id t = v[@"timeout"];
  int s = [t isKindOfClass:[NSNumber class]] ? [t intValue] : 0;
  return s > 0 ? s : 120;
}

int credlock_window_run(const char *json) {
  @autoreleasepool {
    NSDictionary *v = parse(json);
    if (!v) {
      return CREDLOCK_WINDOW_ERROR;
    }
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

    __block int left = timeoutOf(v);
    CLWindow *w = build(v, left);
    void (^finish)(NSModalResponse) = ^(NSModalResponse answer) {
      [NSApp stopModalWithCode:answer];
      // stopModal takes effect when the next event arrives, and a timer
      // firing isn't one.
      [NSApp postEvent:[NSEvent otherEventWithType:NSEventTypeApplicationDefined
                                          location:NSZeroPoint
                                     modifierFlags:0
                                         timestamp:0
                                      windowNumber:0
                                           context:nil
                                           subtype:0
                                             data1:0
                                             data2:0]
               atStart:NO];
    };
    w.deny.onPress = ^{
      finish(kDeny);
    };
    w.allow.onPress = ^{
      finish(kAllow);
    };
    w.panel.onEscape = ^{
      finish(kDeny);
    };

    // Allow wakes after a second; the countdown ends in a denial.
    w.allow.armed = NO;
    NSTimer *timer = [NSTimer timerWithTimeInterval:1
                                            repeats:YES
                                              block:^(NSTimer *t) {
                                                left--;
                                                w.allow.armed = YES;
                                                w.countdown.stringValue = remaining(left > 0 ? left : 0);
                                                if (left <= 0) {
                                                  [t invalidate];
                                                  finish(kTimedOut);
                                                }
                                              }];
    [[NSRunLoop currentRunLoop] addTimer:timer forMode:NSRunLoopCommonModes];

    w.panel.level = NSFloatingWindowLevel;
    w.panel.collectionBehavior =
        NSWindowCollectionBehaviorCanJoinAllSpaces | NSWindowCollectionBehaviorFullScreenAuxiliary;
    [w.panel center];
    if (@available(macOS 14.0, *)) {
      [NSApp activate];
    } else {
      [NSApp activateIgnoringOtherApps:YES];
    }
    [w.panel makeKeyAndOrderFront:nil];
    NSModalResponse answer = [NSApp runModalForWindow:w.panel];
    [timer invalidate];
    [w.panel orderOut:nil];
    switch (answer) {
      case kAllow:
        return CREDLOCK_WINDOW_ALLOW;
      case kTimedOut:
        return CREDLOCK_WINDOW_TIMED_OUT;
      default:
        return CREDLOCK_WINDOW_DENY;
    }
  }
}

int credlock_window_snapshot(const char *json, const char *path, int dark) {
  @autoreleasepool {
    NSDictionary *v = parse(json);
    if (!v) {
      return -1;
    }
    [NSApplication sharedApplication];
    CLWindow *w = build(v, timeoutOf(v));
    NSAppearance *look = [NSAppearance appearanceNamed:dark ? NSAppearanceNameDarkAqua : NSAppearanceNameAqua];
    w.panel.appearance = look;
    NSView *view = w.panel.contentView;
    [view layoutSubtreeIfNeeded];
    __block NSData *png = nil;
    [look performAsCurrentDrawingAppearance:^{
      NSBitmapImageRep *rep = [view bitmapImageRepForCachingDisplayInRect:view.bounds];
      [view cacheDisplayInRect:view.bounds toBitmapImageRep:rep];
      png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    }];
    return png && [png writeToFile:[NSString stringWithUTF8String:path] atomically:YES] ? 0 : -1;
  }
}
