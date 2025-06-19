package com.perimeterx.mobile_sdk.web_view_interception;

import android.webkit.WebView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b {
    public final WebView a;
    public String b;

    public b(WebView webView) {
        Intrinsics.checkNotNullParameter(webView, "webView");
        this.a = webView;
    }
}
