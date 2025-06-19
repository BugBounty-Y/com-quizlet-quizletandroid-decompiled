package com.facebook.internal;

import android.app.ProgressDialog;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Bundle;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ProgressBar;
import androidx.recyclerview.widget.C1372j;
import com.facebook.FacebookDialogException;
import com.facebook.FacebookRequestError;
import com.facebook.FacebookServiceException;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.internal.ads.AbstractC1972di;
import com.google.android.gms.internal.ads.C1895bs;
import com.google.android.gms.internal.ads.zzavm;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.quizletandroid.databinding.C4607k;
import com.quizlet.quizletandroid.ui.webpages.WebViewActivity;
import java.util.ArrayList;
import java.util.regex.Pattern;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class L extends WebViewClient {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ L(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.webkit.WebViewClient
    public void onPageFinished(WebView view, String url) {
        ProgressDialog progressDialog;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(url, "url");
                super.onPageFinished(view, url);
                S s = (S) this.b;
                if (!s.j && (progressDialog = s.e) != null) {
                    progressDialog.dismiss();
                }
                FrameLayout frameLayout = s.g;
                if (frameLayout != null) {
                    frameLayout.setBackgroundColor(0);
                }
                Q q = s.d;
                if (q != null) {
                    q.setVisibility(0);
                }
                ImageView imageView = s.f;
                if (imageView != null) {
                    imageView.setVisibility(0);
                }
                s.k = true;
                break;
            case 1:
            case 2:
            case 3:
            default:
                super.onPageFinished(view, url);
                break;
            case 4:
                if (Intrinsics.b(url, "file:///android_asset/")) {
                    ((Function0) this.b).invoke();
                    break;
                }
                break;
            case 5:
                if (Intrinsics.b(url, "file:///android_asset/")) {
                    ((io.reactivex.rxjava3.internal.operators.completable.d) this.b).onComplete();
                    break;
                }
                break;
            case 6:
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(url, "url");
                ProgressBar progressBar = ((C4607k) ((WebViewActivity) this.b).K()).d;
                Intrinsics.checkNotNullExpressionValue(progressBar, "progressBar");
                progressBar.setVisibility(8);
                break;
        }
    }

    @Override // android.webkit.WebViewClient
    public void onPageStarted(WebView view, String url, Bitmap bitmap) {
        ProgressDialog progressDialog;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(url, "url");
                com.facebook.o oVar = com.facebook.o.a;
                super.onPageStarted(view, url, bitmap);
                S s = (S) obj;
                if (s.j || (progressDialog = s.e) == null) {
                    return;
                }
                progressDialog.show();
                return;
            case 6:
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(url, "url");
                WebViewActivity webViewActivity = (WebViewActivity) obj;
                com.quizlet.features.consent.onetrust.d dVar = webViewActivity.r;
                if (dVar == null) {
                    Intrinsics.m("consentManager");
                    throw null;
                }
                dVar.c(webViewActivity.b0());
                ProgressBar progressBar = ((C4607k) webViewActivity.K()).d;
                Intrinsics.checkNotNullExpressionValue(progressBar, "progressBar");
                progressBar.setVisibility(0);
                return;
            default:
                super.onPageStarted(view, url, bitmap);
                return;
        }
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedError(WebView webView, WebResourceRequest webResourceRequest, WebResourceError webResourceError) {
        switch (this.a) {
            case 1:
                com.google.android.gms.ads.internal.i iVar = (com.google.android.gms.ads.internal.i) this.b;
                InterfaceC1622x interfaceC1622x = iVar.g;
                if (interfaceC1622x != null) {
                    try {
                        interfaceC1622x.r(AbstractC1972di.x(1, null, null));
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
                    }
                }
                InterfaceC1622x interfaceC1622x2 = iVar.g;
                if (interfaceC1622x2 != null) {
                    try {
                        interfaceC1622x2.u(0);
                        break;
                    } catch (RemoteException e2) {
                        com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
                        return;
                    }
                }
                break;
            default:
                super.onReceivedError(webView, webResourceRequest, webResourceError);
                break;
        }
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(handler, "handler");
                Intrinsics.checkNotNullParameter(error, "error");
                super.onReceivedSslError(view, handler, error);
                handler.cancel();
                ((S) this.b).e(new FacebookDialogException(null, -11, null));
                break;
            default:
                super.onReceivedSslError(view, handler, error);
                break;
        }
    }

    @Override // android.webkit.WebViewClient
    public boolean onRenderProcessGone(WebView webView, RenderProcessGoneDetail renderProcessGoneDetail) {
        switch (this.a) {
            case 2:
                Log.w("NativeBridge", "WebView renderer gone: " + renderProcessGoneDetail.toString() + "for WebView: " + String.valueOf(webView));
                C1895bs c1895bs = (C1895bs) this.b;
                if (c1895bs.a() == webView) {
                    Log.w("NativeBridge", "Deallocating the Native bridge as it is unusable. No further events will be generated for this session.");
                    c1895bs.b = new androidx.compose.runtime.internal.m(null);
                }
                webView.destroy();
                return true;
            case 3:
                Log.w("NativeBridge", "WebView renderer gone: " + renderProcessGoneDetail.toString() + "for WebView: " + webView);
                com.iab.omid.library.amazon.publisher.c cVar = (com.iab.omid.library.amazon.publisher.c) this.b;
                if (cVar.e() == webView) {
                    Log.w("NativeBridge", "Deallocating the Native bridge as it is unusable. No further events will be generated for this session.");
                    cVar.b = new androidx.compose.runtime.internal.m(null);
                }
                webView.destroy();
                return true;
            default:
                return super.onRenderProcessGone(webView, renderProcessGoneDetail);
        }
    }

    @Override // android.webkit.WebViewClient
    public boolean shouldOverrideUrlLoading(WebView view, String url) throws NumberFormatException {
        int i;
        int iN = 0;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(url, "url");
                com.facebook.o oVar = com.facebook.o.a;
                Uri uri = Uri.parse(url);
                boolean z = uri.getPath() != null && Pattern.matches("^/(v\\d+\\.\\d+/)??dialog/.*", uri.getPath());
                S s = (S) obj;
                if (!kotlin.text.D.r(url, s.b, false)) {
                    if (kotlin.text.D.r(url, "fbconnect://cancel", false)) {
                        s.cancel();
                        return true;
                    }
                    if (!z && !StringsKt.G(url, "touch", false)) {
                        try {
                            s.getContext().startActivity(new Intent("android.intent.action.VIEW", Uri.parse(url)));
                            return true;
                        } catch (ActivityNotFoundException unused) {
                        }
                    }
                    return false;
                }
                Bundle bundleC = s.c(url);
                String string = bundleC.getString("error");
                if (string == null) {
                    string = bundleC.getString("error_type");
                }
                String string2 = bundleC.getString("error_msg");
                if (string2 == null) {
                    string2 = bundleC.getString("error_message");
                }
                if (string2 == null) {
                    string2 = bundleC.getString("error_description");
                }
                String string3 = bundleC.getString("error_code");
                if (string3 == null || J.D(string3)) {
                    i = -1;
                } else {
                    try {
                        i = Integer.parseInt(string3);
                    } catch (NumberFormatException unused2) {
                    }
                }
                if (J.D(string) && J.D(string2) && i == -1) {
                    M m = s.c;
                    if (m == null || s.i) {
                        return true;
                    }
                    s.i = true;
                    m.a(bundleC, null);
                    s.dismiss();
                    return true;
                }
                if (string != null && (string.equals("access_denied") || string.equals("OAuthAccessDeniedException"))) {
                    s.cancel();
                    return true;
                }
                if (i == 4201) {
                    s.cancel();
                    return true;
                }
                s.e(new FacebookServiceException(new FacebookRequestError(i, string, string2), string2));
                return true;
            case 1:
                com.google.android.gms.ads.internal.i iVar = (com.google.android.gms.ads.internal.i) obj;
                if (url.startsWith(iVar.p())) {
                    return false;
                }
                if (url.startsWith("gmsg://noAdLoaded")) {
                    InterfaceC1622x interfaceC1622x = iVar.g;
                    if (interfaceC1622x != null) {
                        try {
                            interfaceC1622x.r(AbstractC1972di.x(3, null, null));
                        } catch (RemoteException e) {
                            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
                        }
                    }
                    InterfaceC1622x interfaceC1622x2 = iVar.g;
                    if (interfaceC1622x2 != null) {
                        try {
                            interfaceC1622x2.u(3);
                        } catch (RemoteException e2) {
                            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
                        }
                    }
                    iVar.e4(0);
                    return true;
                }
                if (url.startsWith("gmsg://scriptLoadFailed")) {
                    InterfaceC1622x interfaceC1622x3 = iVar.g;
                    if (interfaceC1622x3 != null) {
                        try {
                            interfaceC1622x3.r(AbstractC1972di.x(1, null, null));
                        } catch (RemoteException e3) {
                            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e3);
                        }
                    }
                    InterfaceC1622x interfaceC1622x4 = iVar.g;
                    if (interfaceC1622x4 != null) {
                        try {
                            interfaceC1622x4.u(0);
                        } catch (RemoteException e4) {
                            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e4);
                        }
                    }
                    iVar.e4(0);
                    return true;
                }
                boolean zStartsWith = url.startsWith("gmsg://adResized");
                Context context = iVar.d;
                if (zStartsWith) {
                    InterfaceC1622x interfaceC1622x5 = iVar.g;
                    if (interfaceC1622x5 != null) {
                        try {
                            interfaceC1622x5.zzi();
                        } catch (RemoteException e5) {
                            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e5);
                        }
                    }
                    String queryParameter = Uri.parse(url).getQueryParameter(OTUXParamsKeys.OT_UX_HEIGHT);
                    if (!TextUtils.isEmpty(queryParameter)) {
                        try {
                            com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
                            iN = com.google.android.gms.ads.internal.util.client.c.n(context, Integer.parseInt(queryParameter));
                        } catch (NumberFormatException unused3) {
                        }
                    }
                    iVar.e4(iN);
                    return true;
                }
                if (url.startsWith("gmsg://")) {
                    return true;
                }
                InterfaceC1622x interfaceC1622x6 = iVar.g;
                if (interfaceC1622x6 != null) {
                    try {
                        interfaceC1622x6.q();
                        iVar.g.g();
                    } catch (RemoteException e6) {
                        com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e6);
                    }
                }
                if (iVar.h != null) {
                    Uri uriA = Uri.parse(url);
                    try {
                        uriA = iVar.h.a(uriA, context, null, null);
                    } catch (zzavm e7) {
                        com.google.android.gms.ads.internal.util.client.i.i("Unable to process ad data", e7);
                    }
                    url = uriA.toString();
                }
                Intent intent = new Intent("android.intent.action.VIEW");
                intent.setData(Uri.parse(url));
                context.startActivity(intent);
                return true;
            default:
                return super.shouldOverrideUrlLoading(view, url);
        }
    }

    @Override // android.webkit.WebViewClient
    public void onReceivedError(WebView view, int i, String description, String failingUrl) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(description, "description");
                Intrinsics.checkNotNullParameter(failingUrl, "failingUrl");
                super.onReceivedError(view, i, description, failingUrl);
                ((S) this.b).e(new FacebookDialogException(description, i, failingUrl));
                break;
            default:
                super.onReceivedError(view, i, description, failingUrl);
                break;
        }
    }

    @Override // android.webkit.WebViewClient
    public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
        okhttp3.s sVarD;
        com.quizlet.infra.androidcontracts.deeplink.a aVarF;
        switch (this.a) {
            case 6:
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(request, "request");
                String str = WebViewActivity.u;
                WebViewActivity webViewActivity = (WebViewActivity) this.b;
                Uri url = request.getUrl();
                Intrinsics.checkNotNullExpressionValue(url, "getUrl(...)");
                if (!com.quizlet.quizletandroid.ui.webpages.a.d(url)) {
                    Uri url2 = request.getUrl();
                    Intrinsics.checkNotNullExpressionValue(url2, "getUrl(...)");
                    if (com.quizlet.quizletandroid.ui.webpages.a.a.a(webViewActivity, url2)) {
                        return true;
                    }
                    webViewActivity.finish();
                    return true;
                }
                com.quizlet.data.repository.login.a aVar = webViewActivity.s;
                if (aVar != null) {
                    String url3 = request.getUrl().toString();
                    Intrinsics.checkNotNullExpressionValue(url3, "toString(...)");
                    Intrinsics.checkNotNullParameter(url3, "url");
                    Intrinsics.checkNotNullParameter(url3, "<this>");
                    try {
                        Intrinsics.checkNotNullParameter(url3, "<this>");
                        C1372j c1372j = new C1372j();
                        c1372j.l(null, url3);
                        sVarD = c1372j.d();
                    } catch (IllegalArgumentException unused) {
                        sVarD = null;
                    }
                    if (sVarD == null) {
                        aVarF = null;
                    } else {
                        ArrayList arrayList = sVarD.f;
                        String str2 = (String) CollectionsKt.firstOrNull(arrayList);
                        if (str2 != null && str2.equalsIgnoreCase("explanations")) {
                            aVarF = ((com.quizlet.quizletandroid.deeplinks.a) aVar.a).a(url3, arrayList, ((com.quizlet.infra.legacysyncengine.managers.d) aVar.c).r != null);
                        } else {
                            aVarF = ((com.quizlet.quizletandroid.deeplinks.a) aVar.b).f(url3);
                        }
                    }
                    if (aVarF == null) {
                        return false;
                    }
                    if (!request.hasGesture()) {
                        return true;
                    }
                    com.quizlet.quizletandroid.managers.deeplinks.h hVar = webViewActivity.t;
                    if (hVar != null) {
                        webViewActivity.startActivities(aVarF.c(webViewActivity, hVar));
                        return true;
                    }
                    Intrinsics.m("uriAllowlistedChecker");
                    throw null;
                }
                Intrinsics.m("webViewDeepLinkUseCase");
                throw null;
            default:
                return super.shouldOverrideUrlLoading(view, request);
        }
    }
}
