package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public abstract class U1 {
    public final Q1 a;
    public InterfaceC2380n0 b;
    public C2695uF c;
    public S1 d;
    public long e;
    public long f;
    public long g;
    public int h;
    public int i;
    public Fi j;
    public long k;
    public boolean l;
    public boolean m;

    public U1() {
        Q1 q1 = new Q1();
        q1.d = new R1();
        q1.e = new Kn(0, new byte[65025]);
        q1.b = -1;
        this.a = q1;
        this.j = new Fi();
    }

    public abstract long a(Kn kn);

    public void b(boolean z) {
        int i;
        if (z) {
            this.j = new Fi();
            this.f = 0L;
            i = 0;
        } else {
            i = 1;
        }
        this.h = i;
        this.e = -1L;
        this.g = 0L;
    }

    public abstract boolean c(Kn kn, long j, Fi fi);

    public void d(long j) {
        this.g = j;
    }
}
