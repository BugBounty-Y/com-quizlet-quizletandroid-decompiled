package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.u1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2681u1 {
    public final int a;
    public int b;
    public int c;
    public long d;
    public final boolean e;
    public final Kn f;
    public final Kn g;
    public int h;
    public int i;

    public C2681u1(Kn kn, Kn kn2, boolean z) throws zzaz {
        this.g = kn;
        this.f = kn2;
        this.e = z;
        kn2.j(12);
        this.a = kn2.C();
        kn.j(12);
        this.i = kn.C();
        AbstractC2096gb.q("first_chunk must be 1", kn.u() == 1);
        this.b = -1;
    }

    public final boolean a() {
        int i = this.b + 1;
        this.b = i;
        if (i == this.a) {
            return false;
        }
        boolean z = this.e;
        Kn kn = this.f;
        this.d = z ? kn.I() : kn.H();
        if (this.b == this.h) {
            Kn kn2 = this.g;
            this.c = kn2.C();
            kn2.k(4);
            int i2 = this.i - 1;
            this.i = i2;
            this.h = i2 > 0 ? (-1) + kn2.C() : -1;
        }
        return true;
    }
}
