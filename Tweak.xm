#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <unistd.h>

/*
 * ShazamSigCapture-for-iOS (v1.2 / 診断ビルド)
 *
 * v1.1 で inject は成功（バナー表示）＆認識も実行されたが key.json/last-request.json
 * がどちらも書かれなかった＝署名ヘッダを持つリクエストが、フック中の経路
 * （__NSURLSessionLocal / NSURLSession のタスク生成、NSMutableURLRequest の
 *   addValue:/setValue:forHTTPHeaderField:）を一度も通っていないことが判明。
 *
 * このビルドの目的は「実際に何が Shazam プロセス内を通っているか」を可視化すること。
 *  ・全 dataTask/uploadTask/downloadTask 生成で URL host を1行ログ。
 *  ・host が itunes / shazam / amp のリクエストは、URL とヘッダ名を全部ダンプ。
 *  ・セッションの HTTPAdditionalHeaders も併合して見る（署名がセッション側に載る場合対策）。
 *  ・addValue:/setValue: で「署名/timestamp っぽいヘッダ名」がセットされた瞬間もログ。
 * これで
 *   (A) itunes/amp のリクエストは通るが署名ヘッダが無い → 付与は下層(CFNetwork)か別具象
 *   (B) itunes のトークン要求自体が現れない            → デーモン側で送信＝アプリ注入では不可
 * を切り分ける。捕まえられた場合は従来通り Documents/key.json も書く。
 */

static NSString *const kTag        = @"ShazamSigCapture";
static NSString *const kOutputFile = @"key.json";
static NSString *const kDebugFile  = @"last-request.json";

static NSArray<NSString *> *SignatureKeys(void) {
    static NSArray *a; static dispatch_once_t t;
    dispatch_once(&t, ^{ a = @[ @"x-apple-actionsignature",
                                @"x-aml-sig",
                                @"x-apple-action-signature" ]; });
    return a;
}
static NSArray<NSString *> *TimestampKeys(void) {
    static NSArray *a; static dispatch_once_t t;
    dispatch_once(&t, ^{ a = @[ @"x-request-timestamp",
                                @"x-apple-request-timestamp",
                                @"x-apple-i-md-rinfo" ]; });
    return a;
}

static NSString *gLastPair = nil;

// ── 診断ログをファイルにも書く（syslog が見られなくてもコンテナダンプで回収できる）──
static NSString *gLogPath = nil;
static dispatch_queue_t gLogQ = NULL;

static void AppendLine(NSString *path, NSString *line) {
    if (path.length == 0) return;
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:path]) [[NSData data] writeToFile:path atomically:YES];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) return;
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } @catch (__unused NSException *e) {}
}

static void SCLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[%@] %@", kTag, msg);
    NSString *ts = [NSDateFormatter localizedStringFromDate:[NSDate date]
                        dateStyle:NSDateFormatterNoStyle timeStyle:NSDateFormatterMediumStyle];
    NSString *line = [NSString stringWithFormat:@"%@  %@\n", ts, msg];
    NSString *path = gLogPath;
    if (path && gLogQ) dispatch_async(gLogQ, ^{ AppendLine(path, line); });
}

static NSDictionary<NSString *, NSString *> *LowercaseHeaders(NSDictionary *headers) {
    if (![headers isKindOfClass:NSDictionary.class]) return @{};
    NSMutableDictionary *out = [NSMutableDictionary dictionaryWithCapacity:headers.count];
    for (NSString *k in headers) {
        id v = headers[k];
        if ([k isKindOfClass:NSString.class] && [v isKindOfClass:NSString.class]) {
            out[k.lowercaseString] = v;
        }
    }
    return out;
}

static NSString *FirstMatch(NSDictionary<NSString *, NSString *> *lower, NSArray<NSString *> *cands) {
    for (NSString *c in cands) { NSString *v = lower[c]; if (v.length > 0) return v; }
    return nil;
}

static BOOL FieldMatches(NSString *field, NSArray<NSString *> *cands) {
    if (![field isKindOfClass:NSString.class]) return NO;
    NSString *lc = field.lowercaseString;
    for (NSString *c in cands) if ([lc isEqualToString:c]) return YES;
    return NO;
}

// 「署名/timestamp っぽい」名前かどうか（正確な候補を外していても気付けるよう緩めに）
static BOOL LooksSuspicious(NSString *field) {
    if (![field isKindOfClass:NSString.class]) return NO;
    NSString *lc = field.lowercaseString;
    return ([lc containsString:@"signature"] || [lc containsString:@"sig"] ||
            [lc containsString:@"timestamp"] || [lc containsString:@"i-md-"] ||
            [lc containsString:@"aml"] || [lc containsString:@"mescal"] ||
            [lc containsString:@"token"]);
}

static BOOL IsInterestingHost(NSURL *url) {
    NSString *h = url.host.lowercaseString;
    if (h.length == 0) return NO;
    return ([h containsString:@"itunes"] || [h containsString:@"shazam"] ||
            [h containsString:@"amp"]    || [h containsString:@"aidn"] ||
            [h containsString:@"apple.com"]);
}

static NSString *DocumentsDir(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:docs
                              withIntermediateDirectories:YES attributes:nil error:NULL];
    return docs;
}

static void ShowBanner(NSString *text) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIWindow *win = nil;
            for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
                if ([s isKindOfClass:UIWindowScene.class] &&
                    s.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *w in ((UIWindowScene *)s).windows)
                        if (w.isKeyWindow) { win = w; break; }
                }
                if (win) break;
            }
            UIViewController *root = win.rootViewController;
            while (root.presentedViewController) root = root.presentedViewController;
            if (!root) return;
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:kTag message:text
                                             preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [root presentViewController:ac animated:YES completion:nil];
        } @catch (__unused NSException *e) {}
    });
}

static void WriteKeyJSON(NSString *signature, NSString *timestamp,
                         NSString *url, NSDictionary<NSString *, NSString *> *lower) {
    @try {
        NSString *docs = DocumentsDir();
        NSDictionary *keyObj = @{ @"apple_action_signature": signature ?: @"",
                                  @"x_request_timestamp":    timestamp ?: @"" };
        [[NSJSONSerialization dataWithJSONObject:keyObj options:NSJSONWritingPrettyPrinted error:NULL]
            writeToFile:[docs stringByAppendingPathComponent:kOutputFile] atomically:YES];
        NSDictionary *dbg = @{ @"captured_at": @((long long)([NSDate date].timeIntervalSince1970 * 1000)),
                               @"url": url ?: @"?", @"headers": lower ?: @{} };
        [[NSJSONSerialization dataWithJSONObject:dbg options:NSJSONWritingPrettyPrinted error:NULL]
            writeToFile:[docs stringByAppendingPathComponent:kDebugFile] atomically:YES];
        SCLog(@"★★ 書き出し完了 → %@", [docs stringByAppendingPathComponent:kOutputFile]);
        ShowBanner([NSString stringWithFormat:@"Shazam 署名を取得しました\nts=%@", timestamp ?: @"?"]);
    } @catch (NSException *e) { SCLog(@"書き出し失敗: %@", e.reason); }
}

static void HandleHeaders(NSString *url, NSDictionary *rawHeaders) {
    @try {
        NSDictionary<NSString *, NSString *> *lower = LowercaseHeaders(rawHeaders);
        NSString *signature = FirstMatch(lower, SignatureKeys());
        if (signature.length == 0) return;
        NSString *timestamp = FirstMatch(lower, TimestampKeys());
        if (timestamp.length == 0) { SCLog(@"署名は来たが timestamp 未着 url=%@", url ?: @"?"); return; }
        NSString *pair = [NSString stringWithFormat:@"%@|%@", signature, timestamp];
        if ([pair isEqualToString:gLastPair]) return;
        gLastPair = [pair copy];
        SCLog(@"★署名+timestamp 検出 url=%@ ts=%@", url ?: @"?", timestamp);
        WriteKeyJSON(signature, timestamp, url, lower);
    } @catch (NSException *e) { SCLog(@"HandleHeaders 失敗: %@", e.reason); }
}

// セッションの追加ヘッダ + リクエストヘッダを併合
static NSDictionary *MergedHeaders(NSURLSession *session, NSURLRequest *request) {
    NSMutableDictionary *m = [NSMutableDictionary dictionary];
    @try {
        NSDictionary *add = session.configuration.HTTPAdditionalHeaders;
        if ([add isKindOfClass:NSDictionary.class]) [m addEntriesFromDictionary:add];
    } @catch (__unused NSException *e) {}
    NSDictionary *rh = request.allHTTPHeaderFields;
    if ([rh isKindOfClass:NSDictionary.class]) [m addEntriesFromDictionary:rh];
    return m;
}

// ── iOS Shazam の match/v2 は Authorization ベアラで認証している。
//    Apple 署名ではなく、この Authorization 値こそが採取対象。shazam.com の
//    リクエスト（特に /match/v2/）から値ごと抜いて shazam-auth.json に書く。──
static NSString *gLastAuth = nil;
static BOOL gGotMatchV2 = NO;

static void CaptureAuth(NSURLRequest *request, NSDictionary *headers) {
    @try {
        NSString *auth = nil;
        for (NSString *k in headers)
            if ([k caseInsensitiveCompare:@"Authorization"] == NSOrderedSame) { auth = headers[k]; break; }
        if (auth.length == 0) return;

        BOOL isMatch = [request.URL.path containsString:@"/match/v2/"];
        if (!isMatch && gGotMatchV2) return;                        // match/v2 を採れたら他で上書きしない
        if (!isMatch && [auth isEqualToString:gLastAuth]) return;   // 同値の重複は避ける
        gLastAuth = [auth copy];

        NSString *docs = DocumentsDir();

        // リクエストボディ（match/v2 の JSON、Content-Type: application/json）を採る。
        // POST の本体は通常 HTTPBody(NSData)。読み取りは非破壊。ストリームなら消費を避けフラグだけ。
        NSData *body = request.HTTPBody;
        NSString *bodyText = nil;
        if (body.length > 0) {
            bodyText = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
            if (isMatch)   // match/v2 の生ボディは別ファイルにも保存（そのまま再現に使える）
                [body writeToFile:[docs stringByAppendingPathComponent:@"shazam-match-v2-body.json"] atomically:YES];
        }
        BOOL hasStream = (request.HTTPBodyStream != nil);

        NSMutableDictionary *obj = [@{
            @"captured_at":    @((long long)([NSDate date].timeIntervalSince1970 * 1000)),
            @"is_match_v2":    @(isMatch),
            @"url":            request.URL.absoluteString ?: @"",
            @"method":         request.HTTPMethod ?: @"",
            @"body_bytes":     @(body.length),
            @"body_is_stream": @(hasStream),
            @"headers":        headers ?: @{},
        } mutableCopy];
        if (bodyText.length > 0)      obj[@"body_text"]   = bodyText;                              // JSONならそのまま読める
        else if (body.length > 0)     obj[@"body_base64"] = [body base64EncodedStringWithOptions:0]; // 非UTF8時の保険

        [[NSJSONSerialization dataWithJSONObject:obj options:NSJSONWritingPrettyPrinted error:NULL]
            writeToFile:[docs stringByAppendingPathComponent:@"shazam-auth.json"] atomically:YES];
        if (isMatch) gGotMatchV2 = YES;

        SCLog(@"★ 採取 → shazam-auth.json (match_v2=%d authLen=%lu body=%luB) %@",
              isMatch, (unsigned long)auth.length, (unsigned long)body.length, request.URL.path ?: @"?");
        ShowBanner([NSString stringWithFormat:@"Authorization 採取%@\n%@",
                    isMatch ? @" (match/v2)" : @"", request.URL.path ?: @"?"]);
    } @catch (NSException *e) { SCLog(@"CaptureAuth 失敗: %@", e.reason); }
}

// タスク生成時の共通処理（診断ログ＋捕捉）
static void InspectTask(id sessionObj, NSURLRequest *request, NSString *kind) {
    if (![request isKindOfClass:NSURLRequest.class]) return;
    NSURLSession *session = (NSURLSession *)sessionObj;   // __NSURLSessionLocal も NSURLSession として扱う
    @try {
        NSURL *url = request.URL;
        NSDictionary *merged = MergedHeaders(session, request);

        // 全タスクを1行（host のみ）
        SCLog(@"task[%@] host=%@ hdrs=%lu", kind, url.host ?: @"?", (unsigned long)merged.count);

        // 注目ホストは中身をダンプ
        if (IsInterestingHost(url)) {
            NSArray *names = [merged.allKeys sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
            NSDictionary<NSString *,NSString *> *lower = LowercaseHeaders(merged);
            BOOL hasSig = (FirstMatch(lower, SignatureKeys()).length > 0);
            NSMutableArray *susp = [NSMutableArray array];
            for (NSString *n in names) if (LooksSuspicious(n)) [susp addObject:n];
            SCLog(@"  ↳ INTERESTING url=%@", url.absoluteString);
            SCLog(@"     headerNames=%@", [names componentsJoinedByString:@", "]);
            SCLog(@"     hasKnownSig=%d suspiciousNames=[%@]",
                  hasSig, [susp componentsJoinedByString:@", "]);
        }
        HandleHeaders(url.absoluteString, merged);

        // ★本命：shazam.com リクエストから Authorization を採取
        if ([url.host.lowercaseString hasSuffix:@"shazam.com"]) CaptureAuth(request, merged);
    } @catch (__unused NSException *e) {}
}

// ── __NSURLSessionLocal（iOS13+ の実体）──
%hook __NSURLSessionLocal
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)r {
    InspectTask(self, r, @"data"); return %orig;
}
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)r
                            completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))ch {
    InspectTask(self, r, @"data+ch"); return %orig;
}
- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)r fromData:(NSData *)d {
    InspectTask(self, r, @"upload"); return %orig;
}
- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)r fromData:(NSData *)d
                                completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))ch {
    InspectTask(self, r, @"upload+ch"); return %orig;
}
- (NSURLSessionUploadTask *)uploadTaskWithStreamedRequest:(NSURLRequest *)r {
    InspectTask(self, r, @"upload-stream"); return %orig;
}
- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)r {
    InspectTask(self, r, @"download"); return %orig;
}
- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)r
                                    completionHandler:(void (^)(NSURL *, NSURLResponse *, NSError *))ch {
    InspectTask(self, r, @"download+ch"); return %orig;
}
%end

// ── 公開 NSURLSession（保険）──
%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)r {
    InspectTask(self, r, @"data(pub)"); return %orig;
}
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)r
                            completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))ch {
    InspectTask(self, r, @"data+ch(pub)"); return %orig;
}
%end

// ── NSMutableURLRequest のヘッダ設定（addValue/setValue）──
// ※独立関数だと環境により -Wunused-function を誤検出することがあったため、
//   フック本体に直接インライン化している。
%hook NSMutableURLRequest
- (void)addValue:(NSString *)value forHTTPHeaderField:(NSString *)field {
    %orig;
    (void)value;
    @try {
        BOOL known = FieldMatches(field, SignatureKeys()) || FieldMatches(field, TimestampKeys());
        if (LooksSuspicious(field) || known)
            SCLog(@"header set(add): '%@' host=%@ (known=%d)", field, self.URL.host ?: @"?", known);
        if (known) HandleHeaders(self.URL.absoluteString, self.allHTTPHeaderFields);
    } @catch (__unused NSException *e) {}
}
- (void)setValue:(NSString *)value forHTTPHeaderField:(NSString *)field {
    %orig;
    (void)value;
    @try {
        BOOL known = FieldMatches(field, SignatureKeys()) || FieldMatches(field, TimestampKeys());
        if (LooksSuspicious(field) || known)
            SCLog(@"header set(set): '%@' host=%@ (known=%d)", field, self.URL.host ?: @"?", known);
        if (known) HandleHeaders(self.URL.absoluteString, self.allHTTPHeaderFields);
    } @catch (__unused NSException *e) {}
}
%end

%ctor {
    gLogQ = dispatch_queue_create("com.anony.shazamsigcap.log", DISPATCH_QUEUE_SERIAL);

    // 書き込み可否テスト：Documents / tmp / Library/Caches に sigcap-boot.txt を書いてみる。
    // どこに残るかはコンテナダンプで分かる＝「書けない領域では？」の仮説をダンプだけで検証できる。
    NSString *home = NSHomeDirectory();
    NSArray<NSString *> *cands = @[ [home stringByAppendingPathComponent:@"Documents"],
                                    [home stringByAppendingPathComponent:@"tmp"],
                                    [home stringByAppendingPathComponent:@"Library/Caches"] ];
    NSMutableArray<NSString *> *writable = [NSMutableArray array];
    NSMutableString *report = [NSMutableString stringWithString:@"=== writability test ===\n"];
    for (NSString *dir in cands) {
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES attributes:nil error:NULL];
        NSString *marker = [dir stringByAppendingPathComponent:@"sigcap-boot.txt"];
        NSError *err = nil;
        BOOL ok = [[NSString stringWithFormat:@"boot %@ pid=%d\nhome=%@\n", [NSDate date], getpid(), home]
                    writeToFile:marker atomically:YES encoding:NSUTF8StringEncoding error:&err];
        NSLog(@"[%@] writable? %@ -> %d (%@)", kTag, dir, ok, err.localizedDescription ?: @"ok");
        [report appendFormat:@"%@ %@ (%@)\n", ok ? @"OK" : @"NG", dir, err.localizedDescription ?: @"ok"];
        if (ok) [writable addObject:dir];
    }
    gLogPath = [(writable.firstObject ?: cands.firstObject) stringByAppendingPathComponent:@"sigcap-debug.log"];
    [report appendFormat:@"log  -> %@\nhome -> %@\n\n", gLogPath, home];
    AppendLine(gLogPath, report);   // 最初に書けた場所へ（Documents が NG でも tmp/Caches に残る）

    SCLog(@"injected (bundle=%@) v1.5-bodycapture", NSBundle.mainBundle.bundleIdentifier);
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidBecomeActiveNotification
                    object:nil queue:[NSOperationQueue mainQueue]
                usingBlock:^(__unused NSNotification *n) {
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            SCLog(@"active (bundle=%@)", NSBundle.mainBundle.bundleIdentifier);
            ShowBanner(@"ShazamSigCapture 有効 (v1.5 body採取)");
        });
    }];
}
