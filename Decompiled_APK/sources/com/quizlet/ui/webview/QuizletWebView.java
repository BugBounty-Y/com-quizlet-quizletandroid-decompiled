package com.quizlet.ui.webview;

import android.content.Context;
import android.util.AttributeSet;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import com.perimeterx.mobile_sdk.PerimeterX;
import com.quizlet.humansecurity.d;
import com.quizlet.quizletandroid.v;
import dagger.hilt.android.internal.managers.f;
import dagger.hilt.internal.b;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletWebView extends WebView implements b {
    public f a;
    public final boolean b;
    public com.quizlet.infra.androidcontracts.webview.a c;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QuizletWebView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final void setupWebViewClient(WebViewClient webViewClient) {
        d dVar = (d) getWebViewClientManager();
        dVar.getClass();
        Intrinsics.checkNotNullParameter(this, "webView");
        if (dVar.a.c) {
            PerimeterX.INSTANCE.setupWebView(this, webViewClient);
        } else if (webViewClient != null) {
            setWebViewClient(webViewClient);
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.a == null) {
            this.a = new f(this);
        }
        return this.a.d();
    }

    @NotNull
    public final WebViewClient getQWebViewClient() {
        WebViewClient webViewClient = getWebViewClient();
        Intrinsics.checkNotNullExpressionValue(webViewClient, "getWebViewClient(...)");
        return webViewClient;
    }

    @NotNull
    public final com.quizlet.infra.androidcontracts.webview.a getWebViewClientManager() {
        com.quizlet.infra.androidcontracts.webview.a aVar = this.c;
        if (aVar != null) {
            return aVar;
        }
        Intrinsics.m("webViewClientManager");
        throw null;
    }

    public final void setQWebViewClient(@NotNull WebViewClient value) {
        Intrinsics.checkNotNullParameter(value, "value");
        setupWebViewClient(value);
    }

    @Override // android.webkit.WebView
    public void setWebViewClient(@NotNull WebViewClient client) {
        Intrinsics.checkNotNullParameter(client, "client");
        super.setWebViewClient(client);
    }

    public final void setWebViewClientManager(@NotNull com.quizlet.infra.androidcontracts.webview.a aVar) {
        Intrinsics.checkNotNullParameter(aVar, "<set-?>");
        this.c = aVar;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QuizletWebView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public QuizletWebView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        if (!isInEditMode() && !this.b) {
            this.b = true;
            this.c = (com.quizlet.infra.androidcontracts.webview.a) ((v) ((a) d())).a.I1.get();
        }
        setupWebViewClient(null);
    }
}
