package com.amazon.aps.ads.util.adview;

import android.webkit.RenderProcessGoneDetail;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import androidx.compose.animation.d0;
import com.amazon.device.ads.DTBAdView;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3538u;
import java.io.IOException;
import java.io.InputStream;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h extends i {
    public final e b;
    public final com.airbnb.lottie.network.c c;

    public h(e webviewClientListener) {
        Intrinsics.checkNotNullParameter(webviewClientListener, "webviewClientListener");
        this.b = webviewClientListener;
        this.c = new com.airbnb.lottie.network.c(webviewClientListener);
    }

    public final WebResourceResponse a(String str) throws IOException {
        try {
            InputStream inputStreamOpen = this.b.getAdViewContext().getAssets().open(str);
            Intrinsics.checkNotNullExpressionValue(inputStreamOpen, "webviewClientListener.ad…ext.assets.open(jsScript)");
            return new WebResourceResponse("image/png", "UTF-8", inputStreamOpen);
        } catch (Exception e) {
            String strK = Intrinsics.k(str, "Failed to get injection response: ");
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(2, 1, strK, e);
            return null;
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onPageFinished(WebView webView, String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        AbstractC3538u.a(this, Intrinsics.k(url, "Page load completed: "));
        this.b.onPageFinished(url, webView);
    }

    @Override // android.webkit.WebViewClient
    public final void onReceivedError(WebView webView, WebResourceRequest webResourceRequest, WebResourceError webResourceError) {
        super.onReceivedError(webView, webResourceRequest, webResourceError);
        AbstractC3538u.b(this, "WebView client received OnReceivedError");
        try {
            this.b.onLoadError();
        } catch (RuntimeException e) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute onReceivedError method", e);
        }
    }

    @Override // android.webkit.WebViewClient
    public final boolean onRenderProcessGone(WebView webView, RenderProcessGoneDetail detail) {
        Intrinsics.checkNotNullParameter(detail, "detail");
        super.onRenderProcessGone(webView, detail);
        this.a = true;
        AbstractC3538u.b(this, "WebView client crashed");
        StringBuilder sb = new StringBuilder("Fail to render ad due to webView crash.");
        if (webView == null) {
            return true;
        }
        this.b.onCrash(webView, sb, webView instanceof DTBAdView ? d0.s(new Object[]{Boolean.valueOf(detail.didCrash()), Integer.valueOf(detail.rendererPriorityAtExit())}, 2, "Webview didCrash :%s , Webview rendererPriorityAtExit : %d", "format(format, *args)") : "");
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0033  */
    @Override // android.webkit.WebViewClient
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.webkit.WebResourceResponse shouldInterceptRequest(android.webkit.WebView r5, java.lang.String r6) {
        /*
            r4 = this;
            r0 = 1
            java.lang.String r1 = "Should intercept Resource url: "
            java.lang.String r1 = kotlin.jvm.internal.Intrinsics.k(r6, r1)     // Catch: java.lang.RuntimeException -> L49
            com.google.android.gms.internal.mlkit_vision_common.AbstractC3538u.a(r4, r1)     // Catch: java.lang.RuntimeException -> L49
            if (r6 != 0) goto Ld
            goto L4b
        Ld:
            r1 = 0
            java.util.Locale r2 = java.util.Locale.US     // Catch: java.lang.RuntimeException -> L30
            java.lang.String r3 = "US"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r3)     // Catch: java.lang.RuntimeException -> L30
            java.lang.String r2 = r6.toLowerCase(r2)     // Catch: java.lang.RuntimeException -> L30
            java.lang.String r3 = "this as java.lang.String).toLowerCase(locale)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r3)     // Catch: java.lang.RuntimeException -> L30
            android.net.Uri r2 = android.net.Uri.parse(r2)     // Catch: java.lang.RuntimeException -> L30
            if (r2 != 0) goto L25
            goto L30
        L25:
            java.lang.String r3 = "local"
            java.lang.String r2 = r2.getScheme()     // Catch: java.lang.RuntimeException -> L30
            boolean r2 = r3.equals(r2)     // Catch: java.lang.RuntimeException -> L30
            goto L31
        L30:
            r2 = r1
        L31:
            if (r2 == 0) goto L4b
            r5 = 6
            r2 = 47
            int r5 = kotlin.text.StringsKt.P(r6, r2, r1, r5)     // Catch: java.lang.RuntimeException -> L49
            int r5 = r5 + r0
            java.lang.String r5 = r6.substring(r5)     // Catch: java.lang.RuntimeException -> L49
            java.lang.String r6 = "this as java.lang.String).substring(startIndex)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)     // Catch: java.lang.RuntimeException -> L49
            android.webkit.WebResourceResponse r5 = r4.a(r5)     // Catch: java.lang.RuntimeException -> L49
            return r5
        L49:
            r5 = move-exception
            goto L50
        L4b:
            android.webkit.WebResourceResponse r5 = super.shouldInterceptRequest(r5, r6)     // Catch: java.lang.RuntimeException -> L49
            return r5
        L50:
            java.lang.String r6 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r6)
            java.lang.String r6 = "Fail to execute shouldInterceptRequest method"
            r1 = 2
            com.amazon.aps.shared.a.e(r1, r0, r6, r5)
            r5 = 0
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.amazon.aps.ads.util.adview.h.shouldInterceptRequest(android.webkit.WebView, java.lang.String):android.webkit.WebResourceResponse");
    }

    @Override // android.webkit.WebViewClient
    public final boolean shouldOverrideUrlLoading(WebView webView, String str) {
        if (str == null) {
            return false;
        }
        try {
            if (this.b.isTwoPartExpand()) {
                return false;
            }
            return this.c.v(str);
        } catch (RuntimeException e) {
            Intrinsics.checkNotNullParameter(this, "<this>");
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute shouldOverrideUrlLoading method", e);
            return false;
        }
    }
}
