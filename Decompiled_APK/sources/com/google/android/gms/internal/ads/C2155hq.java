package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.C1614q;
import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.ads.hq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2155hq {
    public final Vp a;
    public final Xp b;
    public final C2584rr c;
    public final C2499pr d;
    public final Tq e;
    public final C2830xf f;

    public C2155hq(C2584rr c2584rr, C2499pr c2499pr, Vp vp, Xp xp, C2830xf c2830xf, Tq tq) {
        this.a = vp;
        this.b = xp;
        this.c = c2584rr;
        this.d = c2499pr;
        this.f = c2830xf;
        this.e = tq;
    }

    public final void a(ArrayList arrayList, Ah ah) {
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            Vp vp = this.a;
            if (vp.i0) {
                String str2 = this.b.b;
                C2499pr c2499pr = this.d;
                c2499pr.getClass();
                com.google.android.gms.ads.internal.j.C.k.getClass();
                com.android.volley.toolbox.d dVar = new com.android.volley.toolbox.d(2, System.currentTimeMillis(), str2, str);
                C2107gm c2107gm = c2499pr.a;
                c2107gm.getClass();
                c2107gm.d(new C1732Mb(26, c2107gm, dVar));
            } else {
                this.c.a(str, vp.x0, this.e, ah);
            }
        }
    }

    public final void b(int i, ArrayList arrayList) {
        com.google.common.util.concurrent.e eVarE;
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.aa)).booleanValue() && C2830xf.b(str)) {
                eVarE = this.f.a(str, C1614q.f.e);
            } else {
                eVarE = AbstractC2025es.E(str);
            }
            com.android.billingclient.api.s sVar = new com.android.billingclient.api.s(this, i, 17);
            eVarE.a(new Qv(0, eVarE, sVar), AbstractC2270kd.a);
        }
    }
}
