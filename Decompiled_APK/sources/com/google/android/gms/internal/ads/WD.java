package com.google.android.gms.internal.ads;

import android.os.Looper;
import android.os.SystemClock;
import android.util.SparseArray;
import java.io.IOException;
import java.util.concurrent.CopyOnWriteArraySet;

/* loaded from: classes2.dex */
public final class WD implements InterfaceC2266kF, InterfaceC2909zE {
    public final C1847ao a;
    public final C2303l9 b;
    public final C2518q9 c;
    public final C2084g6 d;
    public final SparseArray e;
    public com.amazon.aps.ads.privacy.a f;
    public PD g;
    public Bo h;
    public boolean i;

    public WD(C1847ao c1847ao) {
        c1847ao.getClass();
        this.a = c1847ao;
        String str = Yo.a;
        Looper looperMyLooper = Looper.myLooper();
        this.f = new com.amazon.aps.ads.privacy.a(looperMyLooper == null ? Looper.getMainLooper() : looperMyLooper, c1847ao, new C2047fD(28));
        C2303l9 c2303l9 = new C2303l9();
        this.b = c2303l9;
        this.c = new C2518q9();
        C2084g6 c2084g6 = new C2084g6();
        c2084g6.a = c2303l9;
        C2244ju c2244ju = AbstractC2330lu.b;
        c2084g6.b = Bu.e;
        c2084g6.c = Gu.g;
        this.d = c2084g6;
        this.e = new SparseArray();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void a(int i, C2093gF c2093gF, YE ye, androidx.compose.animation.core.S0 s0, IOException iOException, boolean z) {
        RD rdK = k(i, c2093gF);
        i(rdK, 1003, new C2883yp(rdK, ye, s0, iOException, z));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void b(int i, C2093gF c2093gF, androidx.compose.animation.core.S0 s0) {
        RD rdK = k(i, c2093gF);
        i(rdK, 1004, new Fp(rdK, false, s0, 10));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void c(int i, C2093gF c2093gF, YE ye, androidx.compose.animation.core.S0 s0) {
        i(k(i, c2093gF), 1001, new TD(2));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void d(int i, C2093gF c2093gF, YE ye, androidx.compose.animation.core.S0 s0, int i2) {
        i(k(i, c2093gF), 1000, new TD(13));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void e(int i, C2093gF c2093gF, YE ye, androidx.compose.animation.core.S0 s0) {
        i(k(i, c2093gF), 1002, new TD(0));
    }

    public final void f(PD pd, Looper looper) {
        boolean z = true;
        if (this.g != null && !((AbstractC2330lu) this.d.b).isEmpty()) {
            z = false;
        }
        AbstractC1795We.L(z);
        pd.getClass();
        this.g = pd;
        this.h = this.a.a(looper, null);
        com.amazon.aps.ads.privacy.a aVar = this.f;
        Ps ps = new Ps();
        ps.a = this;
        ps.b = pd;
        this.f = new com.amazon.aps.ads.privacy.a((CopyOnWriteArraySet) aVar.f, looper, (C1847ao) aVar.c, ps, aVar.b);
    }

    public final RD g() {
        return j((C2093gF) this.d.d);
    }

    public final RD h(A9 a9, int i, C2093gF c2093gF) {
        C2093gF c2093gF2 = true == a9.o() ? null : c2093gF;
        this.a.getClass();
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        boolean z = false;
        if (a9.equals(this.g.h1()) && i == this.g.a1()) {
            z = true;
        }
        long jW = 0;
        if (c2093gF2 == null || !c2093gF2.b()) {
            if (z) {
                PD pd = this.g;
                pd.d.a();
                C2221jD c2221jD = pd.c;
                c2221jD.U();
                jW = c2221jD.n1(c2221jD.d1);
            } else if (!a9.o()) {
                a9.e(i, this.c, 0L).getClass();
                jW = Yo.w(0L);
            }
        } else if (z && this.g.k1() == c2093gF2.b && this.g.l1() == c2093gF2.c) {
            jW = this.g.n1();
        }
        long j = jW;
        C2093gF c2093gF3 = (C2093gF) this.d.d;
        A9 a9H1 = this.g.h1();
        int iA1 = this.g.a1();
        long jN1 = this.g.n1();
        PD pd2 = this.g;
        pd2.d.a();
        C2221jD c2221jD2 = pd2.c;
        c2221jD2.U();
        return new RD(jElapsedRealtime, a9, i, c2093gF2, j, a9H1, iA1, c2093gF3, jN1, Yo.w(c2221jD2.d1.q));
    }

    public final void i(RD rd, int i, Pk pk) {
        this.e.put(i, rd);
        com.amazon.aps.ads.privacy.a aVar = this.f;
        aVar.d(i, pk);
        aVar.c();
    }

    public final RD j(C2093gF c2093gF) {
        this.g.getClass();
        A9 a9 = c2093gF == null ? null : (A9) ((Gu) this.d.c).get(c2093gF);
        if (c2093gF != null && a9 != null) {
            return h(a9, a9.n(c2093gF.a, this.b).c, c2093gF);
        }
        int iA1 = this.g.a1();
        A9 a9H1 = this.g.h1();
        if (iA1 >= a9H1.c()) {
            a9H1 = A9.a;
        }
        return h(a9H1, iA1, null);
    }

    public final RD k(int i, C2093gF c2093gF) {
        PD pd = this.g;
        pd.getClass();
        if (c2093gF != null) {
            return ((A9) ((Gu) this.d.c).get(c2093gF)) != null ? j(c2093gF) : h(A9.a, i, c2093gF);
        }
        A9 a9H1 = pd.h1();
        if (i >= a9H1.c()) {
            a9H1 = A9.a;
        }
        return h(a9H1, i, null);
    }

    public final RD l() {
        return j((C2093gF) this.d.f);
    }
}
