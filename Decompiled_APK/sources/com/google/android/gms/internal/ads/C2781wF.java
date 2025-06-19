package com.google.android.gms.internal.ads;

import android.os.Looper;
import java.util.concurrent.ExecutorService;

/* renamed from: com.google.android.gms.internal.ads.wF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2781wF extends NE {
    public final InterfaceC2589rw h;
    public final C1 i;
    public final int j;
    public boolean k;
    public long l;
    public boolean m;
    public boolean n;
    public C2050fG o;
    public C2640t3 p;
    public final C2883yp q;

    public /* synthetic */ C2781wF(C2640t3 c2640t3, InterfaceC2589rw interfaceC2589rw, C2883yp c2883yp, TD td, int i) {
        C1 c1 = C1.m;
        this.p = c2640t3;
        this.h = interfaceC2589rw;
        this.q = c2883yp;
        this.i = c1;
        this.j = i;
        this.k = true;
        this.l = -9223372036854775807L;
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void a(InterfaceC2005eF interfaceC2005eF) {
        C2695uF c2695uF = (C2695uF) interfaceC2005eF;
        if (c2695uF.t) {
            for (C2910zF c2910zF : c2695uF.q) {
                c2910zF.l();
                if (c2910zF.A != null) {
                    c2910zF.A = null;
                    c2910zF.f = null;
                }
            }
        }
        C2326lq c2326lq = c2695uF.i;
        HandlerC2094gG handlerC2094gG = (HandlerC2094gG) c2326lq.c;
        if (handlerC2094gG != null) {
            handlerC2094gG.a(true);
        }
        RunnableC2481pF runnableC2481pF = new RunnableC2481pF(c2695uF, 3);
        ExecutorC1859b executorC1859b = (ExecutorC1859b) c2326lq.b;
        executorC1859b.execute(runnableC2481pF);
        ((ExecutorService) executorC1859b.b).shutdown();
        c2695uF.n.removeCallbacksAndMessages(null);
        c2695uF.o = null;
        c2695uF.L = true;
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final InterfaceC2005eF b(C2093gF c2093gF, C1963dG c1963dG, long j) {
        Fw fwMo22zza = this.h.mo22zza();
        C2050fG c2050fG = this.o;
        if (c2050fG != null) {
            fwMo22zza.m(c2050fG);
        }
        V1 v1 = c().b;
        v1.getClass();
        AbstractC1795We.p(this.g);
        X x = (X) this.q.b;
        Iw iw = new Iw();
        iw.c = x;
        C2866yE c2866yE = new C2866yE(this.d.b, c2093gF);
        C2866yE c2866yE2 = new C2866yE(this.c.b, c2093gF);
        long jT = Yo.t(-9223372036854775807L);
        return new C2695uF(v1.a, fwMo22zza, iw, this.i, c2866yE, c2866yE2, this, c1963dG, this.j, jT);
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final synchronized C2640t3 c() {
        return this.p;
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void j(C2050fG c2050fG) {
        this.o = c2050fG;
        Looper.myLooper().getClass();
        AbstractC1795We.p(this.g);
        t();
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void m() {
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final synchronized void p(C2640t3 c2640t3) {
        this.p = c2640t3;
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void r() {
    }

    public final void s(long j, InterfaceC2122h0 interfaceC2122h0, boolean z) {
        if (j == -9223372036854775807L) {
            j = this.l;
        }
        boolean zG = interfaceC2122h0.g();
        if (!this.k && this.l == j && this.m == zG && this.n == z) {
            return;
        }
        this.l = j;
        this.m = zG;
        this.n = z;
        this.k = false;
        t();
    }

    public final void t() {
        long j = this.l;
        boolean z = this.m;
        boolean z2 = this.n;
        C2640t3 c2640t3C = c();
        A9 df = new DF(j, j, z, c2640t3C, z2 ? c2640t3C.c : null);
        if (this.k) {
            df = new C2738vF(df);
        }
        k(df);
    }
}
