package com.google.android.gms.internal.ads;

import android.os.Handler;
import android.webkit.WebView;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.bs, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1895bs extends Zr {
    public WebView e;
    public Long f;
    public final Map g;

    public C1895bs(String str, Map map) {
        super(str);
        this.f = null;
        this.g = map;
    }

    @Override // com.google.android.gms.internal.ads.Zr
    public final void b() {
        super.b();
        new Handler().postDelayed(new RunnableC2104gj(this), Math.max(4000 - (this.f == null ? 4000L : TimeUnit.MILLISECONDS.convert(System.nanoTime() - this.f.longValue(), TimeUnit.NANOSECONDS)), 2000L));
        this.e = null;
    }

    @Override // com.google.android.gms.internal.ads.Zr
    public final void d(Hr hr, C2210j2 c2210j2) {
        JSONObject jSONObject = new JSONObject();
        Map mapUnmodifiableMap = Collections.unmodifiableMap((HashMap) c2210j2.d);
        Iterator it2 = mapUnmodifiableMap.keySet().iterator();
        if (it2.hasNext()) {
            mapUnmodifiableMap.get((String) it2.next()).getClass();
            throw new ClassCastException();
        }
        e(hr, c2210j2, jSONObject);
    }

    @Override // com.google.android.gms.internal.ads.Zr
    public final void f() {
        WebView webView = new WebView(Wr.b.a);
        this.e = webView;
        webView.getSettings().setJavaScriptEnabled(true);
        this.e.getSettings().setAllowContentAccess(false);
        this.e.getSettings().setAllowFileAccess(false);
        this.e.setWebViewClient(new com.facebook.internal.L(this, 2));
        this.b = new androidx.compose.runtime.internal.m(this.e);
        AbstractC1795We.P(this.e, null);
        Map map = this.g;
        Iterator it2 = map.keySet().iterator();
        if (it2.hasNext()) {
            map.get((String) it2.next()).getClass();
            throw new ClassCastException();
        }
        this.f = Long.valueOf(System.nanoTime());
    }
}
