package com.google.android.gms.internal.ads;

import android.webkit.WebView;
import java.util.Date;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class Zr {
    public final String a;
    public long c = System.nanoTime();
    public int d = 1;
    public androidx.compose.runtime.internal.m b = new androidx.compose.runtime.internal.m(null);

    public Zr(String str) {
        this.a = str;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final WebView a() {
        return (WebView) this.b.get();
    }

    public void b() {
        this.b.clear();
    }

    public final void c(Date date) {
        if (date == null) {
            return;
        }
        JSONObject jSONObject = new JSONObject();
        AbstractC1938cs.c(jSONObject, "timestamp", Long.valueOf(date.getTime()));
        AbstractC1795We.o(a(), "setLastActivity", jSONObject);
    }

    public void d(Hr hr, C2210j2 c2210j2) {
        e(hr, c2210j2, null);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0061  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(com.google.android.gms.internal.ads.Hr r7, com.google.android.gms.internal.ads.C2210j2 r8, org.json.JSONObject r9) {
        /*
            Method dump skipped, instructions count: 266
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Zr.e(com.google.android.gms.internal.ads.Hr, com.google.android.gms.internal.ads.j2, org.json.JSONObject):void");
    }

    public void f() {
    }
}
