package com.braze.ui.inappmessage.views;

import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Message;
import android.webkit.ConsoleMessage;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import com.braze.support.BrazeLogger;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class InAppMessageHtmlBaseView$messageWebView$7 extends WebChromeClient {
    final /* synthetic */ boolean $isLinkTargetSupported;
    final /* synthetic */ InAppMessageHtmlBaseView this$0;

    public InAppMessageHtmlBaseView$messageWebView$7(InAppMessageHtmlBaseView inAppMessageHtmlBaseView, boolean z) {
        this.this$0 = inAppMessageHtmlBaseView;
        this.$isLinkTargetSupported = z;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onConsoleMessage$lambda$0(ConsoleMessage consoleMessage) {
        return "Braze HTML In-app Message log. Line: " + consoleMessage.lineNumber() + ". SourceId: " + consoleMessage.sourceId() + ". Log Level: " + consoleMessage.messageLevel() + ". Message: " + consoleMessage.message();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onCreateWindow$lambda$1() {
        return "linkTargetSupport not enabled, passing to super.onCreateWindow()";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onCreateWindow$lambda$2() {
        return "onCreateWindow webView is null, not opening link";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onCreateWindow$lambda$3(WebView.HitTestResult hitTestResult) {
        return "onCreateWindow HitTestResult is " + hitTestResult;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onCreateWindow$lambda$4(WebView.HitTestResult hitTestResult) {
        return "onCreateWindow: hitTestResult type was " + hitTestResult.getType() + ". Not doing anything.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onCreateWindow$lambda$5(WebView.HitTestResult hitTestResult) {
        return "Failed to open link in new window. " + hitTestResult;
    }

    @Override // android.webkit.WebChromeClient
    public Bitmap getDefaultVideoPoster() {
        Bitmap bitmapCreateBitmap = Bitmap.createBitmap(1, 1, Bitmap.Config.ARGB_8888);
        Intrinsics.checkNotNullExpressionValue(bitmapCreateBitmap, "createBitmap(...)");
        return bitmapCreateBitmap;
    }

    @Override // android.webkit.WebChromeClient
    public boolean onConsoleMessage(ConsoleMessage cm) {
        Intrinsics.checkNotNullParameter(cm, "cm");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this.this$0, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.ui.c(cm, 1), 7, (Object) null);
        return true;
    }

    @Override // android.webkit.WebChromeClient
    public boolean onCreateWindow(WebView webView, boolean z, boolean z2, Message message) {
        if (!this.$isLinkTargetSupported) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.ui.inappmessage.listeners.a(11), 6, (Object) null);
            return super.onCreateWindow(webView, z, z2, message);
        }
        if (webView == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.ui.inappmessage.listeners.a(12), 6, (Object) null);
            return false;
        }
        final WebView.HitTestResult hitTestResult = webView.getHitTestResult();
        Intrinsics.checkNotNullExpressionValue(hitTestResult, "getHitTestResult(...)");
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.Priority priority = BrazeLogger.Priority.V;
        final int i = 0;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, new Function0() { // from class: com.braze.ui.inappmessage.views.b
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        return InAppMessageHtmlBaseView$messageWebView$7.onCreateWindow$lambda$3(hitTestResult);
                    case 1:
                        return InAppMessageHtmlBaseView$messageWebView$7.onCreateWindow$lambda$4(hitTestResult);
                    default:
                        return InAppMessageHtmlBaseView$messageWebView$7.onCreateWindow$lambda$5(hitTestResult);
                }
            }
        }, 6, (Object) null);
        try {
            int type = hitTestResult.getType();
            if (type == 2) {
                this.this$0.getContext().startActivity(new Intent("android.intent.action.VIEW", Uri.parse("tel:" + hitTestResult.getExtra())));
                return false;
            }
            if (type == 4) {
                this.this$0.getContext().startActivity(new Intent("android.intent.action.VIEW", Uri.parse("mailto:" + hitTestResult.getExtra())));
                return false;
            }
            if (type != 7) {
                final int i2 = 1;
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, new Function0() { // from class: com.braze.ui.inappmessage.views.b
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i2) {
                            case 0:
                                return InAppMessageHtmlBaseView$messageWebView$7.onCreateWindow$lambda$3(hitTestResult);
                            case 1:
                                return InAppMessageHtmlBaseView$messageWebView$7.onCreateWindow$lambda$4(hitTestResult);
                            default:
                                return InAppMessageHtmlBaseView$messageWebView$7.onCreateWindow$lambda$5(hitTestResult);
                        }
                    }
                }, 6, (Object) null);
                return false;
            }
            this.this$0.getContext().startActivity(new Intent("android.intent.action.VIEW", Uri.parse(hitTestResult.getExtra())));
            return false;
        } catch (Exception e) {
            final int i3 = 2;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, new Function0() { // from class: com.braze.ui.inappmessage.views.b
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    switch (i3) {
                        case 0:
                            return InAppMessageHtmlBaseView$messageWebView$7.onCreateWindow$lambda$3(hitTestResult);
                        case 1:
                            return InAppMessageHtmlBaseView$messageWebView$7.onCreateWindow$lambda$4(hitTestResult);
                        default:
                            return InAppMessageHtmlBaseView$messageWebView$7.onCreateWindow$lambda$5(hitTestResult);
                    }
                }
            }, 4, (Object) null);
            return false;
        }
    }
}
