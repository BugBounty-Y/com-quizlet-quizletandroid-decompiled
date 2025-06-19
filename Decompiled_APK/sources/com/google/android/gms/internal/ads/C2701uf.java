package com.google.android.gms.internal.ads;

import android.content.Context;
import android.text.TextUtils;
import android.webkit.CookieManager;
import java.util.HashMap;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.uf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2701uf implements InterfaceC2315lf {
    public final CookieManager a;

    public C2701uf(Context context) {
        com.google.android.gms.ads.internal.j.C.f.getClass();
        this.a = com.google.android.gms.ads.internal.util.G.b();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2315lf
    public final void a(HashMap map) {
        CookieManager cookieManager = this.a;
        if (cookieManager == null) {
            return;
        }
        if (((String) map.get("clear")) == null) {
            String str = (String) map.get("cookie");
            if (TextUtils.isEmpty(str)) {
                return;
            }
            cookieManager.setCookie((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T0), str);
            return;
        }
        String str2 = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T0);
        String cookie = cookieManager.getCookie(str2);
        if (cookie != null) {
            List listK = C2883yp.e(new C2501pt(';')).k(cookie);
            for (int i = 0; i < listK.size(); i++) {
                String str3 = (String) listK.get(i);
                C2883yp c2883ypE = C2883yp.e(new C2501pt('='));
                str3.getClass();
                AbstractC2930zt abstractC2930zt = (AbstractC2930zt) ((At) c2883ypE.b).e(c2883ypE, str3);
                if (!abstractC2930zt.hasNext()) {
                    throw new IndexOutOfBoundsException("position (0) must be less than the number of elements that remained (0)");
                }
                cookieManager.setCookie(str2, String.valueOf((String) abstractC2930zt.next()).concat(String.valueOf((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.F0))));
            }
        }
    }
}
