package com.iab.omid.library.amazon.publisher;

import android.os.Handler;
import android.text.TextUtils;
import android.webkit.WebView;
import androidx.compose.runtime.internal.m;
import com.facebook.internal.L;
import com.google.android.gms.common.api.internal.w;
import com.iab.omid.library.amazon.adsession.d;
import com.iab.omid.library.amazon.adsession.k;
import com.iab.omid.library.amazon.internal.g;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c extends a {
    public WebView f;
    public Long g;
    public final Map h;

    public c(String str, Map map) {
        super(str);
        this.g = null;
        this.h = map;
    }

    @Override // com.iab.omid.library.amazon.publisher.a
    public final void a(k kVar, d dVar) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        Map mapUnmodifiableMap = Collections.unmodifiableMap(dVar.d);
        Iterator it2 = mapUnmodifiableMap.keySet().iterator();
        if (it2.hasNext()) {
            mapUnmodifiableMap.get((String) it2.next()).getClass();
            throw new ClassCastException();
        }
        b(kVar, dVar, jSONObject);
    }

    @Override // com.iab.omid.library.amazon.publisher.a
    public final void d() {
        super.d();
        new Handler().postDelayed(new w(this), Math.max(4000 - (this.g == null ? 4000L : TimeUnit.MILLISECONDS.convert(System.nanoTime() - this.g.longValue(), TimeUnit.NANOSECONDS)), 2000L));
        this.f = null;
    }

    @Override // com.iab.omid.library.amazon.publisher.a
    public final void f() {
        WebView webView = new WebView(g.b.a);
        this.f = webView;
        webView.getSettings().setJavaScriptEnabled(true);
        this.f.getSettings().setAllowContentAccess(false);
        this.f.getSettings().setAllowFileAccess(false);
        this.f.setWebViewClient(new L(this, 3));
        this.b = new m(this.f);
        WebView webView2 = this.f;
        if (webView2 != null && !TextUtils.isEmpty(null)) {
            try {
                webView2.evaluateJavascript(null, null);
            } catch (IllegalStateException unused) {
                webView2.loadUrl("javascript: null");
            }
        }
        Map map = this.h;
        Iterator it2 = map.keySet().iterator();
        if (it2.hasNext()) {
            map.get((String) it2.next()).getClass();
            throw new ClassCastException();
        }
        this.g = Long.valueOf(System.nanoTime());
    }
}
