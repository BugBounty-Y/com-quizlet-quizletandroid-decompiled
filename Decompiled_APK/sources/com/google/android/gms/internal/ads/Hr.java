package com.google.android.gms.internal.ads;

import android.app.ActivityManager;
import android.os.Handler;
import android.provider.Settings;
import android.view.View;
import android.webkit.WebView;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Hr {
    public final C2210j2 a;
    public Zr d;
    public final String g;
    public final Vr b = new Vr();
    public boolean e = false;
    public boolean f = false;
    public androidx.compose.runtime.internal.m c = new androidx.compose.runtime.internal.m(null);

    public Hr(Bs bs, C2210j2 c2210j2, String str) {
        this.a = c2210j2;
        this.g = str;
        Gr gr = Gr.HTML;
        Gr gr2 = (Gr) c2210j2.g;
        if (gr2 == gr || gr2 == Gr.JAVASCRIPT) {
            C1851as c1851as = new C1851as(str);
            WebView webView = (WebView) c2210j2.b;
            if (!webView.getSettings().getJavaScriptEnabled()) {
                webView.getSettings().setJavaScriptEnabled(true);
            }
            c1851as.b = new androidx.compose.runtime.internal.m(webView);
            this.d = c1851as;
        } else {
            this.d = new C1895bs(str, Collections.unmodifiableMap((HashMap) c2210j2.d));
        }
        this.d.f();
        Qr.c.a.add(this);
        Zr zr = this.d;
        WebView webViewA = zr.a();
        JSONObject jSONObject = new JSONObject();
        AbstractC1938cs.c(jSONObject, "impressionOwner", (Mr) bs.b);
        AbstractC1938cs.c(jSONObject, "mediaEventsOwner", (Mr) bs.c);
        AbstractC1938cs.c(jSONObject, "creativeType", (Ir) bs.d);
        AbstractC1938cs.c(jSONObject, "impressionType", (Kr) bs.e);
        AbstractC1938cs.c(jSONObject, "isolateVerificationScripts", Boolean.valueOf(bs.a));
        AbstractC1795We.o(webViewA, "init", jSONObject, zr.a);
    }

    public final void a() {
        if (this.f) {
            return;
        }
        this.c.clear();
        if (!this.f) {
            this.b.a.clear();
        }
        this.f = true;
        Zr zr = this.d;
        AbstractC1795We.o(zr.a(), "finishSession", zr.a);
        Qr qr = Qr.c;
        ArrayList arrayList = qr.a;
        ArrayList arrayList2 = qr.b;
        boolean z = arrayList2.size() > 0;
        arrayList.remove(this);
        arrayList2.remove(this);
        if (z && arrayList2.size() <= 0) {
            Xr xrB = Xr.b();
            xrB.getClass();
            C2157hs c2157hs = C2157hs.g;
            c2157hs.getClass();
            Handler handler = C2157hs.i;
            if (handler != null) {
                handler.removeCallbacks(C2157hs.k);
                C2157hs.i = null;
            }
            c2157hs.a.clear();
            C2157hs.h.post(new RunnableC2104gj(c2157hs, 18));
            Pr pr = Pr.e;
            pr.b = false;
            pr.d = null;
            Nr nr = xrB.b;
            nr.a.getContentResolver().unregisterContentObserver(nr);
        }
        this.d.b();
        this.d = null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void b(View view) {
        if (this.f || ((View) this.c.get()) == view) {
            return;
        }
        this.c = new androidx.compose.runtime.internal.m(view);
        Zr zr = this.d;
        zr.getClass();
        zr.c = System.nanoTime();
        zr.d = 1;
        Collection<Hr> collectionUnmodifiableCollection = Collections.unmodifiableCollection(Qr.c.a);
        if (collectionUnmodifiableCollection == null || collectionUnmodifiableCollection.isEmpty()) {
            return;
        }
        for (Hr hr : collectionUnmodifiableCollection) {
            if (hr != this && ((View) hr.c.get()) == view) {
                hr.c.clear();
            }
        }
    }

    public final void c() {
        if (this.e || this.d == null) {
            return;
        }
        this.e = true;
        ArrayList arrayList = Qr.c.b;
        boolean z = arrayList.size() > 0;
        arrayList.add(this);
        if (!z) {
            Xr xrB = Xr.b();
            xrB.getClass();
            Pr pr = Pr.e;
            pr.d = xrB;
            pr.b = true;
            ActivityManager.RunningAppProcessInfo runningAppProcessInfo = new ActivityManager.RunningAppProcessInfo();
            ActivityManager.getMyMemoryState(runningAppProcessInfo);
            boolean z2 = runningAppProcessInfo.importance == 100 || pr.u();
            pr.c = z2;
            pr.t(z2);
            C2157hs.g.getClass();
            C2157hs.b();
            Nr nr = xrB.b;
            nr.getClass();
            new Thread(new RunnableC2104gj(nr, 16)).start();
            nr.a.getContentResolver().registerContentObserver(Settings.System.CONTENT_URI, true, nr);
        }
        float f = Xr.b().a;
        Zr zr = this.d;
        AbstractC1795We.o(zr.a(), "setDeviceVolume", Float.valueOf(f), zr.a);
        Zr zr2 = this.d;
        Date date = (Date) Or.e.c;
        zr2.c(date != null ? (Date) date.clone() : null);
        this.d.d(this, this.a);
    }
}
