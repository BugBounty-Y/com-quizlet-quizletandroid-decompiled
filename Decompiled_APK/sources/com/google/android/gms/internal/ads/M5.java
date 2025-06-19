package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import android.webkit.ValueCallback;
import android.webkit.WebView;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class M5 implements ValueCallback {
    public final /* synthetic */ C a;
    public final /* synthetic */ J5 b;
    public final /* synthetic */ WebView c;
    public final /* synthetic */ boolean d;

    public /* synthetic */ M5(C c, J5 j5, WebView webView, boolean z) {
        this.a = c;
        this.b = j5;
        this.c = webView;
        this.d = z;
    }

    @Override // android.webkit.ValueCallback
    public final void onReceiveValue(Object obj) {
        boolean z;
        N5 n5 = (N5) this.a.d;
        J5 j5 = this.b;
        WebView webView = this.c;
        String str = (String) obj;
        boolean z2 = this.d;
        n5.getClass();
        synchronized (j5.g) {
            j5.m--;
        }
        try {
            if (!TextUtils.isEmpty(str)) {
                String strOptString = new JSONObject(str).optString("text");
                if (n5.n || TextUtils.isEmpty(webView.getTitle())) {
                    j5.a(strOptString, z2, webView.getX(), webView.getY(), webView.getWidth(), webView.getHeight());
                } else {
                    j5.a(webView.getTitle() + "\n" + strOptString, z2, webView.getX(), webView.getY(), webView.getWidth(), webView.getHeight());
                }
            }
            synchronized (j5.g) {
                z = j5.m == 0;
            }
            if (z) {
                n5.d.i(j5);
            }
        } catch (JSONException unused) {
            com.google.android.gms.ads.internal.util.client.i.d("Json string may be malformed.");
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.k(3);
            com.google.android.gms.ads.internal.j.C.h.h("ContentFetchTask.processWebViewContent", th);
        }
    }
}
