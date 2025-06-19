package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class PD extends AbstractC2863yB {
    public final C2221jD c;
    public final C1973dj d;

    public PD(ZC zc) {
        super(5);
        C1973dj c1973dj = new C1973dj();
        this.d = c1973dj;
        try {
            this.c = new C2221jD(zc, this);
            c1973dj.c();
        } catch (Throwable th) {
            this.d.c();
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final void G() {
        this.d.a();
        this.c.U();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final void X0(int i, long j) {
        this.d.a();
        this.c.X0(i, j);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final int a1() {
        this.d.a();
        return this.c.a1();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final void f1() {
        this.d.a();
        this.c.U();
    }

    public final int g() {
        this.d.a();
        C2221jD c2221jD = this.c;
        c2221jD.U();
        return c2221jD.d1.n;
    }

    public final int h() {
        this.d.a();
        return this.c.h();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final A9 h1() {
        this.d.a();
        return this.c.h1();
    }

    public final int k1() {
        this.d.a();
        C2221jD c2221jD = this.c;
        c2221jD.U();
        if (c2221jD.D1()) {
            return c2221jD.d1.b.b;
        }
        return -1;
    }

    public final int l1() {
        this.d.a();
        C2221jD c2221jD = this.c;
        c2221jD.U();
        if (c2221jD.D1()) {
            return c2221jD.d1.b.c;
        }
        return -1;
    }

    public final long m1() {
        this.d.a();
        C2221jD c2221jD = this.c;
        c2221jD.U();
        if (c2221jD.D1()) {
            GD gd = c2221jD.d1;
            return gd.k.equals(gd.b) ? Yo.w(c2221jD.d1.p) : c2221jD.z1();
        }
        c2221jD.U();
        if (c2221jD.d1.a.o()) {
            return c2221jD.f1;
        }
        GD gd2 = c2221jD.d1;
        long j = 0;
        if (gd2.k.d != gd2.b.d) {
            return Yo.w(gd2.a.e(c2221jD.a1(), (C2518q9) c2221jD.a, 0L).j);
        }
        long j2 = gd2.p;
        if (c2221jD.d1.k.b()) {
            GD gd3 = c2221jD.d1;
            gd3.a.n(gd3.k.a, c2221jD.o).f.a(c2221jD.d1.k.b).getClass();
        } else {
            j = j2;
        }
        GD gd4 = c2221jD.d1;
        gd4.a.n(gd4.k.a, c2221jD.o);
        return Yo.w(j);
    }

    public final long n1() {
        this.d.a();
        return this.c.y1();
    }

    public final long o1() {
        this.d.a();
        return this.c.z1();
    }

    public final C2697ub p1() {
        this.d.a();
        C2221jD c2221jD = this.c;
        c2221jD.U();
        return (C2697ub) c2221jD.d1.i.d;
    }

    public final boolean q1() {
        this.d.a();
        return this.c.C1();
    }

    public final boolean r1() {
        this.d.a();
        return this.c.D1();
    }
}
