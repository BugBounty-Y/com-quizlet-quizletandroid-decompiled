package com.perimeterx.mobile_sdk.web_view_interception;

import android.graphics.Bitmap;
import android.net.http.SslError;
import android.os.Message;
import android.view.KeyEvent;
import android.webkit.ClientCertRequest;
import android.webkit.HttpAuthHandler;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.SafeBrowsingResponse;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.lifecycle.u0;
import com.google.firebase.messaging.u;
import com.perimeterx.mobile_sdk.doctor_app.model.i;
import com.perimeterx.mobile_sdk.session.l;
import com.perimeterx.mobile_sdk.session.m;
import java.net.URL;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g extends WebViewClient {
    public WebViewClient a;
    public u b;

    @Override // android.webkit.WebViewClient
    public final void doUpdateVisitedHistory(WebView webView, String str, boolean z) {
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.doUpdateVisitedHistory(webView, str, z);
        } else {
            super.doUpdateVisitedHistory(webView, str, z);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onFormResubmission(WebView webView, Message dontResend, Message message) {
        Intrinsics.checkNotNullParameter(dontResend, "dontResend");
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onFormResubmission(webView, dontResend, message);
        } else {
            super.onFormResubmission(webView, dontResend, message);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onLoadResource(WebView webView, String str) {
        if (webView != null && str != null && this.b != null) {
            Intrinsics.checkNotNullParameter(webView, "webView");
            webView.evaluateJavascript("(function() { window.addEventListener('pxCaptcha', function(e) { pxCaptcha.handleEvent(JSON.stringify(e.detail)); }) })();", new com.perimeterx.mobile_sdk.block.d(1));
        }
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onLoadResource(webView, str);
        } else {
            super.onLoadResource(webView, str);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onPageCommitVisible(WebView webView, String str) {
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onPageCommitVisible(webView, str);
        } else {
            super.onPageCommitVisible(webView, str);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onPageFinished(WebView webView, String str) {
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onPageFinished(webView, str);
        } else {
            super.onPageFinished(webView, str);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onPageStarted(WebView webView, String url, Bitmap bitmap) {
        u uVar;
        com.perimeterx.mobile_sdk.doctor_app.model.d dVar;
        i iVar;
        String value;
        com.perimeterx.mobile_sdk.session.d dVarB;
        if (webView != null && url != null && (uVar = this.b) != null) {
            Intrinsics.checkNotNullParameter(webView, "webView");
            Intrinsics.checkNotNullParameter(url, "url");
            webView.evaluateJavascript("(function() { window.addEventListener('pxCaptcha', function(e) { pxCaptcha.handleEvent(JSON.stringify(e.detail)); }) })();", new com.perimeterx.mobile_sdk.block.d(1));
            uVar.c(webView, url);
            u0 u0Var = new u0(8, uVar, url);
            String strA = null;
            if (((l) uVar.b) != null) {
                Intrinsics.checkNotNullParameter(url, "url");
                try {
                    dVarB = l.b(new URL(url), com.perimeterx.mobile_sdk.business_logic.b.b);
                } catch (Exception unused) {
                }
                if (dVarB != null) {
                    Intrinsics.checkNotNullParameter(url, "url");
                    com.perimeterx.mobile_sdk.detections.device.a aVarB = new com.quizlet.data.interactor.set.c((m) null, new androidx.camera.camera2.internal.compat.workaround.a()).b(dVarB.e);
                    com.google.mlkit.common.sdkinternal.model.a aVar = dVarB.g;
                    m mVar = dVarB.b;
                    aVar.getClass();
                    value = com.google.mlkit.common.sdkinternal.model.a.h(mVar, aVarB);
                } else {
                    value = null;
                }
                if (value != null) {
                    String str = com.perimeterx.mobile_sdk.configurations.i.a;
                    Intrinsics.checkNotNullParameter("px_mobile_data", "key");
                    Intrinsics.checkNotNullParameter(value, "value");
                    webView.evaluateJavascript(android.support.v4.media.session.a.t(new StringBuilder("(function(){try { sessionStorage.setItem(\"px_mobile_data\", \""), value, "\"); } catch(e) { return \"error\"; } return \"ok\"})()"), new h(u0Var, 0));
                }
            }
            androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
            if (fVar != null) {
                if (((com.perimeterx.mobile_sdk.doctor_app.f) fVar.g) == com.perimeterx.mobile_sdk.doctor_app.f.b && fVar.h() && ((iVar = (dVar = (com.perimeterx.mobile_sdk.doctor_app.model.d) fVar.i).f) == null || !iVar.b)) {
                    String str2 = com.perimeterx.mobile_sdk.configurations.i.a;
                    String uuid = dVar.a;
                    Intrinsics.checkNotNullParameter(uuid, "uuid");
                    strA = com.perimeterx.mobile_sdk.configurations.i.a("PhantomJS/%@", uuid);
                }
                if (!Intrinsics.b(webView.getSettings().getUserAgentString(), strA)) {
                    webView.getSettings().setUserAgentString(strA);
                }
            }
        }
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onPageStarted(webView, url, bitmap);
        } else {
            super.onPageStarted(webView, url, bitmap);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onReceivedClientCertRequest(WebView webView, ClientCertRequest request) {
        Intrinsics.checkNotNullParameter(request, "request");
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onReceivedClientCertRequest(webView, request);
        } else {
            super.onReceivedClientCertRequest(webView, request);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onReceivedError(WebView webView, int i, String str, String str2) {
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onReceivedError(webView, i, str, str2);
        } else {
            super.onReceivedError(webView, i, str, str2);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onReceivedHttpAuthRequest(WebView webView, HttpAuthHandler handler, String str, String str2) {
        Intrinsics.checkNotNullParameter(handler, "handler");
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onReceivedHttpAuthRequest(webView, handler, str, str2);
        } else {
            super.onReceivedHttpAuthRequest(webView, handler, str, str2);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onReceivedHttpError(WebView webView, WebResourceRequest webResourceRequest, WebResourceResponse webResourceResponse) {
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onReceivedHttpError(webView, webResourceRequest, webResourceResponse);
        } else {
            super.onReceivedHttpError(webView, webResourceRequest, webResourceResponse);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onReceivedLoginRequest(WebView webView, String str, String str2, String str3) {
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onReceivedLoginRequest(webView, str, str2, str3);
        } else {
            super.onReceivedLoginRequest(webView, str, str2, str3);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onReceivedSslError(WebView webView, SslErrorHandler handler, SslError sslError) {
        Intrinsics.checkNotNullParameter(handler, "handler");
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onReceivedSslError(webView, handler, sslError);
        } else {
            super.onReceivedSslError(webView, handler, sslError);
        }
    }

    @Override // android.webkit.WebViewClient
    public final boolean onRenderProcessGone(WebView webView, RenderProcessGoneDetail renderProcessGoneDetail) {
        WebViewClient webViewClient = this.a;
        return webViewClient != null ? webViewClient.onRenderProcessGone(webView, renderProcessGoneDetail) : super.onRenderProcessGone(webView, renderProcessGoneDetail);
    }

    @Override // android.webkit.WebViewClient
    public final void onSafeBrowsingHit(WebView webView, WebResourceRequest webResourceRequest, int i, SafeBrowsingResponse callback) {
        Intrinsics.checkNotNullParameter(callback, "callback");
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onSafeBrowsingHit(webView, webResourceRequest, i, callback);
        } else {
            super.onSafeBrowsingHit(webView, webResourceRequest, i, callback);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onScaleChanged(WebView webView, float f, float f2) {
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onScaleChanged(webView, f, f2);
        } else {
            super.onScaleChanged(webView, f, f2);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onTooManyRedirects(WebView webView, Message cancelMsg, Message message) {
        Intrinsics.checkNotNullParameter(cancelMsg, "cancelMsg");
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onTooManyRedirects(webView, cancelMsg, message);
        } else {
            super.onTooManyRedirects(webView, cancelMsg, message);
        }
    }

    @Override // android.webkit.WebViewClient
    public final void onUnhandledKeyEvent(WebView webView, KeyEvent keyEvent) {
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onUnhandledKeyEvent(webView, keyEvent);
        } else {
            super.onUnhandledKeyEvent(webView, keyEvent);
        }
    }

    @Override // android.webkit.WebViewClient
    public final WebResourceResponse shouldInterceptRequest(WebView webView, String str) {
        WebViewClient webViewClient = this.a;
        return webViewClient != null ? webViewClient.shouldInterceptRequest(webView, str) : super.shouldInterceptRequest(webView, str);
    }

    @Override // android.webkit.WebViewClient
    public final boolean shouldOverrideKeyEvent(WebView webView, KeyEvent keyEvent) {
        WebViewClient webViewClient = this.a;
        return webViewClient != null ? webViewClient.shouldOverrideKeyEvent(webView, keyEvent) : super.shouldOverrideKeyEvent(webView, keyEvent);
    }

    @Override // android.webkit.WebViewClient
    public final boolean shouldOverrideUrlLoading(WebView webView, String str) {
        WebViewClient webViewClient = this.a;
        return webViewClient != null ? webViewClient.shouldOverrideUrlLoading(webView, str) : super.shouldOverrideUrlLoading(webView, str);
    }

    @Override // android.webkit.WebViewClient
    public final void onReceivedError(WebView webView, WebResourceRequest request, WebResourceError error) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(error, "error");
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            webViewClient.onReceivedError(webView, request, error);
        } else {
            super.onReceivedError(webView, request, error);
        }
    }

    @Override // android.webkit.WebViewClient
    public final WebResourceResponse shouldInterceptRequest(WebView webView, WebResourceRequest request) {
        Intrinsics.checkNotNullParameter(request, "request");
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            return webViewClient.shouldInterceptRequest(webView, request);
        }
        return super.shouldInterceptRequest(webView, request);
    }

    @Override // android.webkit.WebViewClient
    public final boolean shouldOverrideUrlLoading(WebView webView, WebResourceRequest request) {
        Intrinsics.checkNotNullParameter(request, "request");
        WebViewClient webViewClient = this.a;
        if (webViewClient != null) {
            return webViewClient.shouldOverrideUrlLoading(webView, request);
        }
        return super.shouldOverrideUrlLoading(webView, request);
    }
}
