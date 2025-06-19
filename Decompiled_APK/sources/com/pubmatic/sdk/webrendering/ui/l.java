package com.pubmatic.sdk.webrendering.ui;

import android.annotation.TargetApi;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.comscore.streaming.EventType;
import com.pubmatic.sdk.common.log.POBLog;

/* loaded from: classes2.dex */
public class l extends WebViewClient {
    private j a;
    private boolean b;
    private boolean c;

    @NonNull
    private final k d;

    public l(@NonNull k kVar) {
        this.d = kVar;
    }

    private void a(String str) {
        POBLog.error("POBHTMLViewClient", str, new Object[0]);
        j jVar = this.a;
        if (jVar != null) {
            jVar.onReceivedError(new com.pubmatic.sdk.common.h(1009, str));
        }
    }

    public void disableMultipleOnPageFinished(boolean z) {
        this.b = z;
    }

    @Override // android.webkit.WebViewClient
    public void onPageFinished(WebView webView, String str) {
        j jVar;
        super.onPageFinished(webView, str);
        POBLog.debug("POBHTMLViewClient", "WebView creative loading finished.", new Object[0]);
        if (!this.c && (jVar = this.a) != null) {
            jVar.onPageFinished(webView);
            this.c = this.b;
        }
        webView.setFocusableInTouchMode(true);
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedError(WebView webView, int i, String str, String str2) {
        super.onReceivedError(webView, i, str, str2);
    }

    @Override // android.webkit.WebViewClient
    @TargetApi(EventType.CDN)
    public boolean onRenderProcessGone(WebView webView, RenderProcessGoneDetail renderProcessGoneDetail) {
        if (renderProcessGoneDetail != null) {
            POBLog.error("POBHTMLViewClient", "WebView Render process gone, did it crash? :-> %s, reason: %s", Boolean.valueOf(renderProcessGoneDetail.didCrash()), Integer.valueOf(renderProcessGoneDetail.rendererPriorityAtExit()));
        }
        this.d.onRenderProcessGone();
        return true;
    }

    public void setHTMLClientListener(j jVar) {
        this.a = jVar;
    }

    @Override // android.webkit.WebViewClient
    public boolean shouldOverrideUrlLoading(WebView webView, String str) {
        return super.shouldOverrideUrlLoading(webView, str);
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedError(WebView webView, WebResourceRequest webResourceRequest, WebResourceError webResourceError) {
        super.onReceivedError(webView, webResourceRequest, webResourceError);
        if (webResourceRequest.isForMainFrame()) {
            a(AbstractC0147y.d("WebView received error on page loading. Error : ", webResourceError != null ? webResourceError.toString() : " Not defined"));
        }
    }

    @Override // android.webkit.WebViewClient
    @TargetApi(EventType.VIDEO)
    public boolean shouldOverrideUrlLoading(WebView webView, WebResourceRequest webResourceRequest) {
        boolean zShouldOverrideUrlLoading = super.shouldOverrideUrlLoading(webView, webResourceRequest);
        POBLog.debug("POBHTMLViewClient", "WebView shouldOverrideUrlLoading.. Request redirect = " + webResourceRequest.isRedirect(), new Object[0]);
        if (webResourceRequest.isRedirect() || webResourceRequest.getUrl() == null) {
            return zShouldOverrideUrlLoading;
        }
        String string = webResourceRequest.getUrl().toString();
        j jVar = this.a;
        return jVar != null ? jVar.shouldOverrideUrlLoading(string) : zShouldOverrideUrlLoading;
    }
}
