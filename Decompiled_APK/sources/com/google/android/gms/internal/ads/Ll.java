package com.google.android.gms.internal.ads;

import java.util.Map;

/* loaded from: classes2.dex */
public final class Ll implements Ml {
    public final Map a;
    public final C2227jd b;
    public final Ih c;

    public Ll(Map map, C2227jd c2227jd, Ih ih) {
        this.a = map;
        this.b = c2227jd;
        this.c = ih;
    }

    @Override // com.google.android.gms.internal.ads.Ml
    public final com.google.common.util.concurrent.e a(zzbvl zzbvlVar) {
        this.c.r0(zzbvlVar);
        AbstractC2460ov abstractC2460ovC = AbstractC2025es.C(new zzdwf(3));
        for (String str : ((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.j8)).split(",")) {
            HC hc = (HC) this.a.get(str.trim());
            if (hc != null) {
                abstractC2460ovC = AbstractC2025es.A(abstractC2460ovC, zzdwf.class, new C2439oa(7, hc, zzbvlVar), this.b);
            }
        }
        abstractC2460ovC.a(new Qv(0, abstractC2460ovC, new C2881yn(this, 20)), AbstractC2270kd.g);
        return abstractC2460ovC;
    }
}
