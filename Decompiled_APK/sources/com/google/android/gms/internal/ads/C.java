package com.google.android.gms.internal.ads;

import android.content.ContentValues;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Pair;
import android.webkit.ValueCallback;
import android.webkit.WebView;
import com.google.android.gms.ads.admanager.AdManagerAdView;

/* loaded from: classes2.dex */
public final /* synthetic */ class C implements Runnable {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;
    public final Object d;

    public /* synthetic */ C(int i, Object obj, Object obj2, Object obj3, boolean z) {
        this.a = i;
        this.b = obj2;
        this.c = obj3;
        this.d = obj;
    }

    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        D3 d3;
        switch (this.a) {
            case 0:
                String str = Yo.a;
                WD wd = ((SurfaceHolderCallbackC2091gD) ((Fi) this.b).c).a.r;
                RD rdL = wd.l();
                wd.i(rdL, 1017, new UD(rdL, (C1832aG) this.c, (RC) this.d));
                return;
            case 1:
                B3 b3 = (B3) this.b;
                synchronized (b3.e) {
                }
                androidx.browser.customtabs.k kVar = (androidx.browser.customtabs.k) this.c;
                zzaqd zzaqdVar = (zzaqd) kVar.d;
                if (zzaqdVar == null) {
                    b3.e(kVar.b);
                } else {
                    synchronized (b3.e) {
                        d3 = b3.f;
                    }
                    d3.x(zzaqdVar);
                }
                if (kVar.a) {
                    b3.d("intermediate-response");
                } else {
                    b3.f("done");
                }
                Qv qv = (Qv) this.d;
                if (qv != null) {
                    qv.run();
                    return;
                }
                return;
            case 2:
                M5 m5 = (M5) this.b;
                WebView webView = (WebView) this.c;
                if (webView.getSettings().getJavaScriptEnabled()) {
                    try {
                        webView.evaluateJavascript("(function() { return  {text:document.body.innerText}})();", m5);
                        return;
                    } catch (Throwable unused) {
                        m5.onReceiveValue("");
                        return;
                    }
                }
                return;
            case 3:
                AdManagerAdView adManagerAdView = (AdManagerAdView) this.b;
                if (adManagerAdView.zzb((com.google.android.gms.ads.internal.client.K) this.c)) {
                    ((BinderC1869b9) this.d).a.a(adManagerAdView);
                    return;
                } else {
                    com.google.android.gms.ads.internal.util.client.i.h("Could not bind.");
                    return;
                }
            case 4:
                C2785wd c2785wd = ((TextureViewSurfaceTextureListenerC2613sd) this.d).q;
                if (c2785wd != null) {
                    c2785wd.c("error", "what", (String) this.b, "extra", (String) this.c);
                    return;
                }
                return;
            case 5:
                super/*android.webkit.WebView*/.evaluateJavascript((String) this.c, (ValueCallback) this.d);
                return;
            case 6:
                ((C2584rr) this.b).a((String) this.c, (com.google.android.gms.auth.api.signin.internal.h) this.d, null, null);
                return;
            case 7:
                ContentValues contentValues = new ContentValues();
                contentValues.put("event_state", (Integer) 1);
                String[] strArr = {(String) this.c};
                SQLiteDatabase sQLiteDatabase = (SQLiteDatabase) this.b;
                sQLiteDatabase.update("offline_buffered_pings", contentValues, "gws_query_id = ?", strArr);
                C2107gm.f(sQLiteDatabase, (com.google.android.gms.ads.internal.util.client.k) this.d);
                return;
            case 8:
                C2158ht c2158ht = (C2158ht) this.b;
                String str2 = c2158ht.b;
                Zs zs = (Zs) this.c;
                androidx.webkit.internal.p pVar = (androidx.webkit.internal.p) this.d;
                try {
                    Tm tm = c2158ht.a;
                    if (tm == null) {
                        throw null;
                    }
                    Ys ys = (Ys) tm.j;
                    if (ys == null) {
                        return;
                    }
                    Bundle bundle = new Bundle();
                    bundle.putString("callerPackage", str2);
                    C2158ht.b(zs.a, new C2026et(bundle, 6));
                    C2158ht.b(zs.b, new C2026et(bundle, 7));
                    BinderC2114gt binderC2114gt = new BinderC2114gt(c2158ht, pVar);
                    Ws ws = (Ws) ys;
                    Parcel parcelF3 = ws.f3();
                    AbstractC2857y5.c(parcelF3, bundle);
                    AbstractC2857y5.e(parcelF3, binderC2114gt);
                    ws.e4(2, parcelF3);
                    return;
                } catch (RemoteException e) {
                    C2158ht.c.b(e, "dismiss overlay display from: %s", str2);
                    return;
                }
            case 9:
                C2158ht c2158ht2 = (C2158ht) this.b;
                String str3 = c2158ht2.b;
                C1896bt c1896bt = (C1896bt) this.c;
                androidx.webkit.internal.p pVar2 = (androidx.webkit.internal.p) this.d;
                try {
                    Tm tm2 = c2158ht2.a;
                    if (tm2 == null) {
                        throw null;
                    }
                    Ys ys2 = (Ys) tm2.j;
                    if (ys2 == null) {
                        return;
                    }
                    Bundle bundle2 = new Bundle();
                    bundle2.putString("callerPackage", str3);
                    bundle2.putBinder("windowToken", c1896bt.a);
                    C2158ht.b(c1896bt.f, new C2026et(bundle2, 8));
                    bundle2.putInt("layoutGravity", c1896bt.c);
                    bundle2.putFloat("layoutVerticalMargin", c1896bt.d);
                    bundle2.putInt("displayMode", 0);
                    bundle2.putInt("triggerMode", 0);
                    bundle2.putInt("windowWidthPx", c1896bt.e);
                    C2158ht.b(null, new C2026et(bundle2, 1));
                    C2158ht.b(null, new C2026et(bundle2, 2));
                    C2158ht.b(c1896bt.b, new C2026et(bundle2, 3));
                    C2158ht.b(null, new C2026et(bundle2, 4));
                    bundle2.putBoolean("stableSessionToken", true);
                    BinderC2114gt binderC2114gt2 = new BinderC2114gt(c2158ht2, pVar2);
                    Ws ws2 = (Ws) ys2;
                    Parcel parcelF32 = ws2.f3();
                    parcelF32.writeString(str3);
                    AbstractC2857y5.c(parcelF32, bundle2);
                    AbstractC2857y5.e(parcelF32, binderC2114gt2);
                    ws2.e4(1, parcelF32);
                    return;
                } catch (RemoteException e2) {
                    C2158ht.c.b(e2, "show overlay display from: %s", str3);
                    return;
                }
            case 10:
                WD wd2 = ((C2822xD) this.b).c;
                Bu buJ = ((C2159hu) this.c).j();
                PD pd = wd2.g;
                pd.getClass();
                C2084g6 c2084g6 = wd2.d;
                c2084g6.getClass();
                c2084g6.b = AbstractC2330lu.n(buJ);
                if (!buJ.isEmpty()) {
                    c2084g6.e = (C2093gF) buJ.get(0);
                    C2093gF c2093gF = (C2093gF) this.d;
                    c2093gF.getClass();
                    c2084g6.f = c2093gF;
                }
                if (((C2093gF) c2084g6.d) == null) {
                    c2084g6.d = C2084g6.t(pd, (AbstractC2330lu) c2084g6.b, (C2093gF) c2084g6.e, (C2303l9) c2084g6.a);
                }
                c2084g6.w(pd.h1());
                return;
            case 11:
                WD wd3 = (WD) ((DD) this.b).b.i;
                Pair pair = (Pair) this.c;
                wd3.b(((Integer) pair.first).intValue(), (C2093gF) pair.second, (androidx.compose.animation.core.S0) this.d);
                return;
            default:
                String str4 = Yo.a;
                WD wd4 = ((SurfaceHolderCallbackC2091gD) ((Fp) this.b).c).a.r;
                RD rdL2 = wd4.l();
                wd4.i(rdL2, 1009, new C2586rt(rdL2, (C1832aG) this.c, (RC) this.d));
                return;
        }
    }

    public /* synthetic */ C(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    public C(N5 n5, J5 j5, WebView webView, boolean z) {
        this.a = 2;
        this.c = webView;
        this.d = n5;
        this.b = new M5(this, j5, webView, z);
    }
}
