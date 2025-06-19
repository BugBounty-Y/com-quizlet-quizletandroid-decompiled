package com.iab.omid.library.amazon.publisher;

import android.webkit.WebView;
import androidx.compose.runtime.internal.m;
import com.iab.omid.library.amazon.adsession.d;
import com.iab.omid.library.amazon.adsession.k;
import com.iab.omid.library.amazon.internal.h;
import java.util.Date;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class a {
    public final String a;
    public com.iab.omid.library.amazon.adsession.a c;
    public long e = System.nanoTime();
    public int d = 1;
    public m b = new m(null);

    public a(String str) {
        this.a = str;
    }

    public void a(k kVar, d dVar) {
        b(kVar, dVar, null);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x005f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(com.iab.omid.library.amazon.adsession.k r7, com.iab.omid.library.amazon.adsession.d r8, org.json.JSONObject r9) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 258
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.iab.omid.library.amazon.publisher.a.b(com.iab.omid.library.amazon.adsession.k, com.iab.omid.library.amazon.adsession.d, org.json.JSONObject):void");
    }

    public final void c(Date date) {
        if (date == null) {
            return;
        }
        JSONObject jSONObject = new JSONObject();
        com.iab.omid.library.amazon.utils.b.b(jSONObject, "timestamp", Long.valueOf(date.getTime()));
        h.a.a(e(), "setLastActivity", jSONObject);
    }

    public void d() {
        this.b.clear();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final WebView e() {
        return (WebView) this.b.get();
    }

    public void f() {
    }
}
