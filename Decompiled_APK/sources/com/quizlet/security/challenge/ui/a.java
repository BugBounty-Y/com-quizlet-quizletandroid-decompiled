package com.quizlet.security.challenge.ui;

import android.graphics.Bitmap;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends WebViewClient {
    public final /* synthetic */ InterfaceC0773a0 a;

    public a(InterfaceC0773a0 interfaceC0773a0) {
        this.a = interfaceC0773a0;
    }

    @Override // android.webkit.WebViewClient
    public final void onPageStarted(WebView view, String str, Bitmap bitmap) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onPageStarted(view, str, bitmap);
        this.a.setValue(Boolean.FALSE);
    }
}
