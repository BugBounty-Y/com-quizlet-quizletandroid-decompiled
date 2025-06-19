package com.perimeterx.mobile_sdk.block;

import android.graphics.Bitmap;
import android.net.Uri;
import android.webkit.CookieManager;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K4;
import com.perimeterx.mobile_sdk.configurations.i;
import java.net.HttpCookie;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public final class e extends WebViewClient {
    public static final /* synthetic */ int c = 0;
    public PXBlockActivity a;
    public PXBlockActivity b;

    public final void a() {
        PXBlockActivity pXBlockActivity = this.b;
        String str = pXBlockActivity != null ? pXBlockActivity.d : null;
        if (str != null) {
            HttpCookie httpCookie = new HttpCookie("_pxmvid", str);
            String str2 = i.a;
            httpCookie.setDomain("perimeterx.net");
            httpCookie.setVersion(0);
            httpCookie.setPath("/");
            CookieManager.getInstance().setAcceptCookie(true);
            CookieManager.getInstance().setCookie(httpCookie.getDomain(), httpCookie.toString());
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onLoadResource(WebView webView, String str) {
        super.onLoadResource(webView, str);
        if (webView != null) {
            webView.evaluateJavascript("(function() { window.addEventListener('pxCaptcha', function(e) { pxCaptcha.handleEvent(JSON.stringify(e.detail)); }) })();", new d(0));
        }
        a();
    }

    @Override // android.webkit.WebViewClient
    public final void onPageStarted(WebView webView, String str, Bitmap bitmap) {
        super.onPageStarted(webView, str, bitmap);
        a();
    }

    @Override // android.webkit.WebViewClient
    public final boolean shouldOverrideUrlLoading(WebView webView, WebResourceRequest webResourceRequest) {
        Uri url;
        String string;
        String str;
        a aVar;
        if (webResourceRequest == null || (url = webResourceRequest.getUrl()) == null || (string = url.toString()) == null) {
            return true;
        }
        if (StringsKt.G(string, "https://perimeterx.net/px/captcha_callback", false)) {
            com.perimeterx.mobile_sdk.models.d dVarC = K4.c(string);
            PXBlockActivity pXBlockActivity = this.a;
            if (pXBlockActivity == null) {
                return true;
            }
            pXBlockActivity.x(dVarC);
            return true;
        }
        if (!StringsKt.G(string, "https://perimeterx.net/px/captcha_close", false)) {
            return true;
        }
        com.perimeterx.mobile_sdk.models.d dVarC2 = K4.c(string);
        if (dVarC2 != null) {
            PXBlockActivity pXBlockActivity2 = this.a;
            if (pXBlockActivity2 == null) {
                return true;
            }
            pXBlockActivity2.x(dVarC2);
            return true;
        }
        PXBlockActivity pXBlockActivity3 = this.a;
        if (pXBlockActivity3 == null || (str = pXBlockActivity3.c) == null || (aVar = (a) PXBlockActivity.e.get(str)) == null) {
            return true;
        }
        aVar.a(pXBlockActivity3);
        return true;
    }
}
