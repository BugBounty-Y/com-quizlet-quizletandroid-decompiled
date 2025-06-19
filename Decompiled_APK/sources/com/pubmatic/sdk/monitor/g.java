package com.pubmatic.sdk.monitor;

import android.content.Context;
import android.content.Intent;
import android.webkit.JavascriptInterface;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.o;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class g extends WebView {
    private List<String> a;
    public boolean isLoaded;

    public class a implements h {
        final /* synthetic */ h a;

        public a(h hVar) {
            this.a = hVar;
        }

        @Override // com.pubmatic.sdk.monitor.h
        public void a() {
            g.this.isLoaded = true;
            this.a.a();
        }

        @Override // com.pubmatic.sdk.monitor.h
        public void b() {
            this.a.b();
        }
    }

    public class b implements Runnable {
        final /* synthetic */ String a;

        public b(String str) {
            this.a = str;
        }

        @Override // java.lang.Runnable
        public void run() {
            g.this.evaluateJavascript(android.support.v4.media.session.a.B("pmMonitor.broadcast('", this.a, "')"), new m(this));
        }
    }

    public static class c {
        Context a;

        public /* synthetic */ c(Context context, a aVar) {
            this(context);
        }

        @JavascriptInterface
        public void nativeCall(String str) {
            JSONObject jSONObject;
            try {
                JSONObject jSONObject2 = new JSONObject(str);
                if (!jSONObject2.optString("name", "").startsWith("share") || (jSONObject = jSONObject2.getJSONObject("params")) == null) {
                    return;
                }
                o.runOnMainThread(new n(this, jSONObject));
            } catch (JSONException e) {
                POBLog.debug("POBMonitorWebView", e.getLocalizedMessage(), new Object[0]);
            }
        }

        private c(Context context) {
            this.a = context;
        }
    }

    public static class d extends WebViewClient {
        h a;

        public /* synthetic */ d(h hVar, a aVar) {
            this(hVar);
        }

        @Override // android.webkit.WebViewClient
        public void onPageFinished(WebView webView, String str) {
            super.onPageFinished(webView, str);
            this.a.a();
        }

        @Override // android.webkit.WebViewClient
        public boolean onRenderProcessGone(WebView webView, RenderProcessGoneDetail renderProcessGoneDetail) {
            POBLog.warn("POBMonitorWebView", "WebView Render process gone.", new Object[0]);
            this.a.b();
            return true;
        }

        @Override // android.webkit.WebViewClient
        public boolean shouldOverrideUrlLoading(WebView webView, WebResourceRequest webResourceRequest) {
            return super.shouldOverrideUrlLoading(webView, webResourceRequest);
        }

        private d(h hVar) {
            this.a = hVar;
        }
    }

    public g(Context context) {
        super(context);
        this.isLoaded = false;
        this.a = new ArrayList();
    }

    public static void a(Context context, String str) {
        Intent intent = new Intent("android.intent.action.SEND");
        intent.putExtra("android.intent.extra.TEXT", str);
        intent.setType("text/plain");
        intent.setFlags(268435456);
        context.getApplicationContext().startActivity(intent);
    }

    public void appendData(JSONObject jSONObject) {
        String string = jSONObject.toString();
        if (!a(string)) {
            this.a.add(string);
            return;
        }
        Iterator<String> it2 = this.a.iterator();
        while (it2.hasNext()) {
            a(it2.next());
            it2.remove();
        }
    }

    public void initWebView(h hVar) {
        getSettings().setJavaScriptEnabled(true);
        clearCache(true);
        clearHistory();
        a aVar = new a(hVar);
        a aVar2 = null;
        setWebViewClient(new d(aVar, aVar2));
        setWebChromeClient(new WebChromeClient());
        addJavascriptInterface(new c(getContext(), aVar2), "nativeBridge");
    }

    private boolean a(String str) {
        if (!this.isLoaded) {
            return false;
        }
        post(new b(str));
        return true;
    }
}
