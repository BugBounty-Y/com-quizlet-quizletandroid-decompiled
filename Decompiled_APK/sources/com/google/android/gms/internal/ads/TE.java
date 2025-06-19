package com.google.android.gms.internal.ads;

import android.os.Handler;
import java.util.HashMap;
import java.util.Iterator;

/* loaded from: classes2.dex */
public abstract class TE extends NE {
    public final HashMap h = new HashMap();
    public Handler i;
    public C2050fG j;

    @Override // com.google.android.gms.internal.ads.NE
    public final void f() {
        for (SE se : this.h.values()) {
            se.a.e(se.b);
        }
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void h() {
        for (SE se : this.h.values()) {
            se.a.g(se.b);
        }
    }

    @Override // com.google.android.gms.internal.ads.NE
    public void m() {
        HashMap map = this.h;
        for (SE se : map.values()) {
            NE ne = se.a;
            ne.l(se.b);
            RE re = se.c;
            ne.o(re);
            ne.n(re);
        }
        map.clear();
    }

    @Override // com.google.android.gms.internal.ads.NE
    public void r() {
        Iterator it2 = this.h.values().iterator();
        while (it2.hasNext()) {
            ((SE) it2.next()).a.r();
        }
    }

    public abstract void s(Integer num, NE ne, A9 a9);

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v2, types: [com.google.android.gms.internal.ads.QE, com.google.android.gms.internal.ads.hF] */
    public final void t(final Integer num, NE ne) {
        HashMap map = this.h;
        AbstractC1795We.B(!map.containsKey(num));
        ?? r1 = new InterfaceC2137hF() { // from class: com.google.android.gms.internal.ads.QE
            @Override // com.google.android.gms.internal.ads.InterfaceC2137hF
            public final void a(NE ne2, A9 a9) {
                this.a.s(num, ne2, a9);
            }
        };
        RE re = new RE(this, num);
        map.put(num, new SE(ne, r1, re));
        Handler handler = this.i;
        handler.getClass();
        C2866yE c2866yE = ne.c;
        c2866yE.getClass();
        c2866yE.b.add(new C2223jF(handler, re));
        this.i.getClass();
        C2866yE c2866yE2 = ne.d;
        c2866yE2.getClass();
        c2866yE2.b.add(new C2823xE(re));
        C2050fG c2050fG = this.j;
        C1917cE c1917cE = this.g;
        AbstractC1795We.p(c1917cE);
        ne.i(r1, c2050fG, c1917cE);
        if (this.b.isEmpty()) {
            ne.e(r1);
        }
    }

    public void u(Integer num) {
    }

    public void v(long j, Integer num) {
    }

    public abstract C2093gF w(Integer num, C2093gF c2093gF);
}
