/* Copyright (c) 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if GTM_INCLUDE_OAUTH2 || (!GTL_REQUIRE_SERVICE_INCLUDES && !GDATA_REQUIRE_SERVICE_INCLUDES)

#define GTMOAUTH2SIGNIN_DEFINE_GLOBALS 1
#import "GTMOAuth2SignIn.h"

// we'll default to timing out if the network becomes unreachable for more
// than 30 seconds when the sign-in page is displayed
static const NSTimeInterval kDefaultNetworkLossTimeoutInterval = 30.0;

// URI indicating an installed app is signing in. This is described at
//
// http://code.google.com/apis/accounts/docs/OAuth2.html#IA
//
NSString *const kOOBString = @"urn:ietf:wg:oauth:2.0:oob";

@interface GTMOAuth2SignIn ()
@property (assign) BOOL hasHandledCallback;
@property (retain) GTMHTTPFetcher *pendingFetcher;

- (void)invokeFinalCallbackWithError:(NSError *)error;

- (BOOL)startWebRequest;
+ (NSMutableURLRequest *)mutableURLRequestWithURL:(NSURL *)oldURL
                                      paramString:(NSString *)paramStr;
- (void)fetchGoogleUserInfo;

- (void)handleCallbackReached;

- (void)auth:(GTMOAuth2Authentication *)auth
finishedWithFetcher:(GTMHTTPFetcher *)fetcher
       error:(NSError *)error;

- (void)infoFetcher:(GTMHTTPFetcher *)fetcher
   finishedWithData:(NSData *)data
              error:(NSError *)error;

- (void)closeTheWindow;

- (void)startReachabilityCheck;
- (void)stopReachabilityCheck;
- (void)reachabilityTarget:(SCNetworkReachabilityRef)reachabilityRef
              changedFlags:(SCNetworkConnectionFlags)flags;
- (void)reachabilityTimerFired:(NSTimer *)timer;
@end

@implementation GTMOAuth2SignIn

@synthesize authentication = auth_;

@synthesize authorizationURL = authorizationURL_;

@synthesize delegate = delegate_;
@synthesize webRequestSelector = webRequestSelector_;
@synthesize finishedSelector = finishedSelector_;
@synthesize hasHandledCallback = hasHandledCallback_;
@synthesize pendingFetcher = pendingFetcher_;
@synthesize userData = userData_;

@synthesize shouldFetchGoogleUserInfo = shouldFetchGoogleUserInfo_;
@synthesize networkLossTimeoutInterval = networkLossTimeoutInterval_;

+ (NSURL *)googleAuthorizationURL {
  NSString *str = @"https://accounts.google.com/o/oauth2/auth";
  return [NSURL URLWithString:str];
}

+ (NSURL *)googleTokenURL {
  NSString *str = @"https://accounts.google.com/o/oauth2/token";
  return [NSURL URLWithString:str];
}

+ (NSString *)googleRedirectURI {
  return kOOBString;
}

+ (GTMOAuth2Authentication *)standardGoogleAuthenticationForScope:(NSString *)scope
                                                         clientID:(NSString *)clientID
                                                     clientSecret:(NSString *)clientSecret {
  NSString *redirectURI = [self googleRedirectURI];
  NSURL *tokenURL = [self googleTokenURL];

  GTMOAuth2Authentication *auth;
  auth = [GTMOAuth2Authentication authenticationWithServiceProvider:kGTMOAuth2ServiceProviderGoogle
                                                           tokenURL:tokenURL
                                                        redirectURI:redirectURI
                                                           clientID:clientID
                                                       clientSecret:clientSecret];
  auth.scope = scope;

  return auth;
}

- (id)initWithAuthentication:(GTMOAuth2Authentication *)auth
            authorizationURL:(NSURL *)authorizationURL
                    delegate:(id)delegate
          webRequestSelector:(SEL)webRequestSelector
            finishedSelector:(SEL)finishedSelector {
  // check the selectors on debug builds
  GTMAssertSelectorNilOrImplementedWithArgs(delegate, webRequestSelector,
    @encode(GTMOAuth2SignIn *), @encode(NSURLRequest *), 0);
  GTMAssertSelectorNilOrImplementedWithArgs(delegate, finishedSelector,
    @encode(GTMOAuth2SignIn *), @encode(GTMOAuth2Authentication *),
    @encode(NSError *), 0);

  // designated initializer
  self = [super init];
  if (self) {
    self.authentication = auth;
    self.authorizationURL = authorizationURL;
    self.delegate = delegate;
    self.webRequestSelector = webRequestSelector;
    self.finishedSelector = finishedSelector;

    // for Google authentication, we want to automatically fetch user info
    NSString *host = [authorizationURL host];
    if ([host isEqual:@"accounts.google.com"]) {
      self.shouldFetchGoogleUserInfo = YES;
    }

    // default timeout for a lost internet connection while the server
    // UI is displayed is 30 seconds
    self.networkLossTimeoutInterval = kDefaultNetworkLossTimeoutInterval;
  }
  return self;
}

- (void)dealloc {
  [self stopReachabilityCheck];

  self.authentication = nil;
  self.authorizationURL = nil;
  self.delegate = nil;
  self.pendingFetcher = nil;
  self.userData = nil;

  [super dealloc];
}

#pragma mark Sign-in Sequence Methods

// stop any pending fetches, and close the window (but don't call the
// delegate's finishedSelector)
- (void)cancelSigningIn {
  [self.pendingFetcher stopFetching];
  self.pendingFetcher = nil;

  [self.authentication stopAuthorization];

  [self closeTheWindow];

  [delegate_ autorelease];
  delegate_ = nil;
}

//
// This is the entry point to begin the sequence
//  - display the authentication web page, and monitor redirects
//  - exchange the code for an access token and a refresh token
//  - for Google sign-in, fetch the user's email address
//  - tell the delegate we're finished
//
- (BOOL)startSigningIn {
  // for signing in to Google, append the scope for obtaining the authenticated
  // user info
  if (shouldFetchGoogleUserInfo_) {
    GTMOAuth2Authentication *auth = self.authentication;

    NSString *const uiScope = @"https://www.googleapis.com/auth/userinfo#email";
    NSString *scope = auth.scope;
    if ([scope rangeOfString:uiScope].location == NSNotFound) {
      scope = [GTMOAuth2Authentication scopeWithStrings:scope, uiScope, nil];
      auth.scope = scope;
    }
  }

  // start the authorization
  return [self startWebRequest];
}

- (BOOL)startWebRequest {
  GTMOAuth2Authentication *auth = self.authentication;
  NSString *clientID = auth.clientID;
  NSString *redirectURI = auth.redirectURI;

  if ([clientID length] == 0 || [redirectURI length] == 0) {
#if DEBUG
    NSAssert([clientID length] > 0, @"GTMOAuth2SignIn: clientID needed");
    NSAssert([redirectURI length] > 0, @"GTMOAuth2SignIn: redirectURI needed");
#endif
    return NO;
  }

  // invoke the UI controller's web request selector to display
  // the authorization page

  // add params to the authorization URL
  NSString *scope = auth.scope;
  if ([scope length] == 0) scope = nil;

  NSDictionary *paramsDict = [NSDictionary dictionaryWithObjectsAndKeys:
                                     @"code", @"response_type",
                                     clientID, @"client_id",
                                     redirectURI, @"redirect_uri",
                                     scope, @"scope", // scope may be nil
                                     nil];
  NSString *paramStr = [GTMOAuth2Authentication encodedQueryParametersForDictionary:paramsDict];

  NSURL *authorizationURL = self.authorizationURL;
  NSMutableURLRequest *request;
  request = [[self class] mutableURLRequestWithURL:authorizationURL
                                       paramString:paramStr];

  [delegate_ performSelector:self.webRequestSelector
                  withObject:self
                  withObject:request];

  // at this point, we're waiting on the server-driven html UI, so
  // we want notification if we lose connectivity to the web server
  [self startReachabilityCheck];
  return YES;
}

// utility for making a request from an old URL with some additional parameters
+ (NSMutableURLRequest *)mutableURLRequestWithURL:(NSURL *)oldURL
                                      paramString:(NSString *)paramStr {
  NSString *query = [oldURL query];
  if ([query length] > 0) {
    query = [query stringByAppendingFormat:@"&%@", paramStr];
  } else {
    query = paramStr;
  }

  NSString *portStr = @"";
  NSString *oldPort = [[oldURL port] stringValue];
  if ([oldPort length] > 0) {
    portStr = [@":" stringByAppendingString:oldPort];
  }

  NSString *qMark = [query length] > 0 ? @"?" : @"";
  NSString *newURLStr = [NSString stringWithFormat:@"%@://%@%@%@%@%@",
                         [oldURL scheme], [oldURL host], portStr,
                         [oldURL path], qMark, query];
  NSURL *newURL = [NSURL URLWithString:newURLStr];
  NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:newURL];
  return request;
}

// entry point for the window controller to tell us that the window
// prematurely closed
- (void)windowWasClosed {
  [self stopReachabilityCheck];

  NSError *error = [NSError errorWithDomain:kGTMOAuth2ErrorDomain
                                       code:kGTMOAuth2ErrorWindowClosed
                                   userInfo:nil];
  [self invokeFinalCallbackWithError:error];
}

// internal method to tell the window controller to close the window
- (void)closeTheWindow {
  [self stopReachabilityCheck];

  // a nil request means the window should be closed
  [delegate_ performSelector:self.webRequestSelector
                  withObject:self
                  withObject:nil];
}

// entry point for the window controller to tell us what web page has been
// requested
//
// When the request is for the callback URL, this method invokes
// handleCallbackReached and returns YES
- (BOOL)requestRedirectedToRequest:(NSURLRequest *)redirectedRequest {
  // for Google's installed app sign-in protocol, we'll look for the
  // end-of-sign-in indicator in the titleChanged: method below
  NSString *redirectURI = self.authentication.redirectURI;

  // when we're searching for the window title string, then we can ignore
  // redirects
  NSString *standardURI = [[self class] googleRedirectURI];
  if ([redirectURI isEqual:standardURI]) return NO;

  // compare the redirectURI, which tells us when the web sign-in is done,
  // to the actual redirection
  NSURL *redirectURL = [NSURL URLWithString:redirectURI];
  NSURL *requestURL = [redirectedRequest URL];

  // avoid comparing to nil host and path values (such as when redirected to
  // "about:blank")
  NSString *requestHost = [requestURL host];
  NSString *requestPath = [requestURL path];
  BOOL isCallback;
  if (requestHost && requestPath) {
    isCallback = [[redirectURL host] isEqual:[requestURL host]]
                 && [[redirectURL path] isEqual:[requestURL path]];
  } else if (requestURL) {
    // handle "about:blank"
    isCallback = [redirectURL isEqual:requestURL];
  } else {
    isCallback = NO;
  }

  if (!isCallback) {
    // tell the caller that this request is nothing interesting
    return NO;
  }

  // we've reached the callback URL

  // try to get the access code
  if (!self.hasHandledCallback) {
    NSString *responseStr = [[redirectedRequest URL] query];
    [self.authentication setKeysForResponseString:responseStr];

#if DEBUG
    NSAssert([self.authentication.code length] > 0
             || [self.authentication.errorString length] > 0,
             @"response lacks auth code or error");
#endif

    [self handleCallbackReached];
  }
  // tell the delegate that we did handle this request
  return YES;
}

// entry point for the window controller to tell us when a new page title has
// been loadded
//
// When the title indicates sign-in has completed, this method invokes
// handleCallbackReached and returns YES
- (BOOL)titleChanged:(NSString *)title {
  // return YES if the OAuth flow ending title was detected

  // right now we're just looking for a parameter list following the last space
  // in the title string, but hopefully we'll eventually get something better
  // from the server to search for
  NSRange paramsRange = [title rangeOfString:@" "
                                     options:NSBackwardsSearch];
  NSUInteger spaceIndex = paramsRange.location;
  if (spaceIndex != NSNotFound) {
    NSString *responseStr = [title substringFromIndex:(spaceIndex + 1)];

    NSDictionary *dict = [GTMOAuth2Authentication dictionaryWithResponseString:responseStr];

    NSString *code = [dict objectForKey:@"code"];
    NSString *error = [dict objectForKey:@"error"];
    if ([code length] > 0 || [error length] > 0) {

      if (!self.hasHandledCallback) {
        [self.authentication setKeysForResponseDictionary:dict];

        [self handleCallbackReached];
      }
      return YES;
    }
  }
  return NO;
}

- (void)handleCallbackReached {
  // the callback page was requested, or the authenticate code was loaded
  // into a page's title, so exchange the auth code for access & refresh tokens
  // and tell the window to close

  // avoid duplicate signals that the callback point has been reached
  self.hasHandledCallback = YES;

  [self closeTheWindow];

  NSError *error = nil;

  GTMOAuth2Authentication *auth = self.authentication;
  NSString *code = auth.code;
  if ([code length] > 0) {
    // exchange the code for a token
    SEL sel = @selector(auth:finishedWithFetcher:error:);
    GTMHTTPFetcher *fetcher = [auth beginTokenFetchWithDelegate:self
                                              didFinishSelector:sel];
    if (fetcher == nil) {
      error = [NSError errorWithDomain:kGTMHTTPFetcherStatusDomain
                                  code:-1
                              userInfo:nil];
    } else {
      self.pendingFetcher = fetcher;
    }
  } else {
    // the callback lacked an auth code
    NSString *errStr = auth.errorString;
    NSDictionary *userInfo = nil;
    if ([errStr length] > 0) {
      userInfo = [NSDictionary dictionaryWithObject:errStr
                                             forKey:kGTMOAuth2ErrorMessageKey];
    }

    error = [NSError errorWithDomain:kGTMOAuth2ErrorDomain
                                code:kGTMOAuth2ErrorAuthorizationFailed
                            userInfo:userInfo];
  }

  if (error) {
    [self invokeFinalCallbackWithError:error];
  }
}

- (void)auth:(GTMOAuth2Authentication *)auth
finishedWithFetcher:(GTMHTTPFetcher *)fetcher
       error:(NSError *)error {
  self.pendingFetcher = nil;

  if (error == nil
      && self.shouldFetchGoogleUserInfo
      && [self.authentication.serviceProvider isEqual:kGTMOAuth2ServiceProviderGoogle]) {
    // fetch the user's information from the Google server
    [self fetchGoogleUserInfo];
  } else {
    // we're not authorizing with Google, so we're done
    [self invokeFinalCallbackWithError:error];
  }
}

- (void)fetchGoogleUserInfo {
  // fetch the user's email address
  NSString *infoURLStr = @"https://www.googleapis.com/userinfo/email";
  NSURL *infoURL = [NSURL URLWithString:infoURLStr];
  NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:infoURL];

  GTMOAuth2Authentication *auth = self.authentication;

  NSString *userAgent = [auth userAgent];
  [request setValue:userAgent forHTTPHeaderField:@"User-Agent"];

  // we can do a synchronous authorization since this method is called
  // only immediately after a fresh access token has been obtained
  [auth authorizeRequest:request];

  GTMHTTPFetcher *fetcher = [GTMHTTPFetcher fetcherWithRequest:request];
  fetcher.retryEnabled = YES;
  fetcher.maxRetryInterval = 15.0;
  fetcher.comment = @"user info";

  [fetcher beginFetchWithDelegate:self
                didFinishSelector:@selector(infoFetcher:finishedWithData:error:)];

  self.pendingFetcher = fetcher;

  [auth notifyFetchIsRunning:YES
                     fetcher:fetcher
                        type:kGTMOAuth2FetchTypeUserInfo];
}

- (void)infoFetcher:(GTMHTTPFetcher *)fetcher
   finishedWithData:(NSData *)data
              error:(NSError *)error {
  GTMOAuth2Authentication *auth = self.authentication;
  [auth notifyFetchIsRunning:NO
                     fetcher:fetcher
                        type:nil];

  self.pendingFetcher = nil;

  if (error) {
#if DEBUG
    if (data) {
      NSString *dataStr = [[[NSString alloc] initWithData:data
                                                 encoding:NSUTF8StringEncoding] autorelease];
      NSLog(@"infoFetcher error: %@\n%@", error, dataStr);
    }
#endif
  } else {
    // we have the authenticated user's info
    if (data) {
      [auth setKeysForResponseData:data];
    }
  }
  [self invokeFinalCallbackWithError:error];
}

// convenience method for making the final call to our delegate
- (void)invokeFinalCallbackWithError:(NSError *)error {
  if (delegate_ && finishedSelector_) {
    GTMOAuth2Authentication *auth = self.authentication;

    NSMethodSignature *sig = [delegate_ methodSignatureForSelector:finishedSelector_];
    NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:sig];
    [invocation setSelector:finishedSelector_];
    [invocation setTarget:delegate_];
    [invocation setArgument:&self atIndex:2];
    [invocation setArgument:&auth atIndex:3];
    [invocation setArgument:&error atIndex:4];
    [invocation invoke];
  }

  // we'll no longer send messages to the delegate
  //
  // we want to autorelease it rather than assign to the property in case
  // the delegate is below us in the call stack
  [delegate_ autorelease];
  delegate_ = nil;
}

#pragma mark Reachability monitoring

static void ReachabilityCallBack(SCNetworkReachabilityRef target,
                                 SCNetworkConnectionFlags flags,
                                 void *info) {
  // pass the flags to the signIn object
  GTMOAuth2SignIn *signIn = (GTMOAuth2SignIn *)info;

  [signIn reachabilityTarget:target
                changedFlags:flags];
}

- (void)startReachabilityCheck {
  // the user may set the timeout to 0 to skip the reachability checking
  // during display of the sign-in page
  if (networkLossTimeoutInterval_ <= 0.0 || reachabilityRef_ != NULL) {
    return;
  }

  // create a reachability target from the authorization URL, add our callback,
  // and schedule it on the run loop so we'll be notified if the network drops
  NSURL *url = self.authorizationURL;
  const char* host = [[url host] UTF8String];
  reachabilityRef_ = SCNetworkReachabilityCreateWithName(kCFAllocatorSystemDefault,
                                                         host);
  if (reachabilityRef_) {
    BOOL isScheduled = NO;
    SCNetworkReachabilityContext ctx = { 0, self, NULL, NULL, NULL };

    if (SCNetworkReachabilitySetCallback(reachabilityRef_,
                                         ReachabilityCallBack, &ctx)) {
      if (SCNetworkReachabilityScheduleWithRunLoop(reachabilityRef_,
                                                   CFRunLoopGetCurrent(),
                                                   kCFRunLoopDefaultMode)) {
        isScheduled = YES;
      }
    }

    if (!isScheduled) {
      CFRelease(reachabilityRef_);
      reachabilityRef_ = NULL;
    }
  }
}

- (void)destroyUnreachabilityTimer {
  [networkLossTimer_ invalidate];
  [networkLossTimer_ autorelease];
  networkLossTimer_ = nil;
}

- (void)reachabilityTarget:(SCNetworkReachabilityRef)reachabilityRef
              changedFlags:(SCNetworkConnectionFlags)flags {
  BOOL isConnected = (flags & kSCNetworkFlagsReachable) != 0
    && (flags & kSCNetworkFlagsConnectionRequired) == 0;

  if (isConnected) {
    // server is again reachable
    [self destroyUnreachabilityTimer];

    if (hasNotifiedNetworkLoss_) {
      // tell the user that the network has been found
      NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
      [nc postNotificationName:kGTMOAuth2NetworkFound
                        object:self
                      userInfo:nil];
      hasNotifiedNetworkLoss_ = NO;
    }
  } else {
    // the server has become unreachable; start the timer, if necessary
    if (networkLossTimer_ == nil
        && networkLossTimeoutInterval_ > 0
        && !hasNotifiedNetworkLoss_) {
      SEL sel = @selector(reachabilityTimerFired:);
      networkLossTimer_ = [[NSTimer scheduledTimerWithTimeInterval:networkLossTimeoutInterval_
                                                            target:self
                                                          selector:sel
                                                          userInfo:nil
                                                           repeats:NO] retain];
    }
  }
}

- (void)reachabilityTimerFired:(NSTimer *)timer {
  // the user may call [[notification object] cancelSigningIn] to
  // dismiss the sign-in
  if (!hasNotifiedNetworkLoss_) {
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc postNotificationName:kGTMOAuth2NetworkLost
                      object:self
                    userInfo:nil];
    hasNotifiedNetworkLoss_ = YES;
  }

  [self destroyUnreachabilityTimer];
}

- (void)stopReachabilityCheck {
  [self destroyUnreachabilityTimer];

  if (reachabilityRef_) {
    SCNetworkReachabilityUnscheduleFromRunLoop(reachabilityRef_,
                                               CFRunLoopGetCurrent(),
                                               kCFRunLoopDefaultMode);
    SCNetworkReachabilitySetCallback(reachabilityRef_, NULL, NULL);

    CFRelease(reachabilityRef_);
    reachabilityRef_ = NULL;
  }
}

#pragma mark Token Revocation

+ (void)revokeTokenForGoogleAuthentication:(GTMOAuth2Authentication *)auth {
  if (auth.canAuthorize
      && [auth.serviceProvider isEqual:kGTMOAuth2ServiceProviderGoogle]) {

    NSString *urlStr = @"https://accounts.google.com/o/oauth2/revoke";
    
    // create a signed revocation request for this authentication object
    NSURL *url = [NSURL URLWithString:urlStr];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    [request setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    
    NSString *token = auth.refreshToken;
    NSString *encoded = [GTMOAuth2Authentication encodedOAuthValueForString:token];
    NSString *body = [@"token=" stringByAppendingString:encoded];
    
    [request setHTTPBody:[body dataUsingEncoding:NSUTF8StringEncoding]];
    [request setHTTPMethod:@"POST"];

    NSString *userAgent = [auth userAgent];
    [request setValue:userAgent forHTTPHeaderField:@"User-Agent"];

    // there's nothing to be done if revocation succeeds or fails
    GTMHTTPFetcher *fetcher = [GTMHTTPFetcher fetcherWithRequest:request];

#if NS_BLOCKS_AVAILABLE
    [fetcher beginFetchWithCompletionHandler:^(NSData *data, NSError *error) {
  #if DEBUG
      if (error) {
        NSString *errStr = [[[NSString alloc] initWithData:data
                                                  encoding:NSUTF8StringEncoding] autorelease];
        NSLog(@"revoke error: %@", errStr);
      }
  #endif
    }];
#else
    [fetcher beginFetchWithDelegate:nil didFinishSelector:NULL];
#endif
  }

  [auth reset];
}

@end

#endif // #if GTM_INCLUDE_OAUTH2 || (!GTL_REQUIRE_SERVICE_INCLUDES && !GDATA_REQUIRE_SERVICE_INCLUDES)

