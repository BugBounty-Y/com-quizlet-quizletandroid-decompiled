package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.Wa, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C1791Wa {
    public final int a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;
    public final boolean g;
    public final boolean h;
    public final Bu i;
    public final Bu j;
    public final Bu k;
    public final int l;
    public final int m;
    public final Bu n;
    public final C2567ra o;
    public final Bu p;
    public final boolean q;
    public final Gu r;
    public final AbstractC2459ou s;

    static {
        new C1791Wa(new C1701Ha());
        String str = Yo.a;
        Integer.toString(1, 36);
        Integer.toString(2, 36);
        Integer.toString(3, 36);
        Integer.toString(4, 36);
        Integer.toString(5, 36);
        Integer.toString(6, 36);
        Integer.toString(7, 36);
        Integer.toString(8, 36);
        Integer.toString(9, 36);
        Integer.toString(10, 36);
        Integer.toString(11, 36);
        Integer.toString(12, 36);
        Integer.toString(13, 36);
        Integer.toString(14, 36);
        Integer.toString(15, 36);
        Integer.toString(16, 36);
        Integer.toString(17, 36);
        Integer.toString(18, 36);
        Integer.toString(19, 36);
        Integer.toString(20, 36);
        Integer.toString(21, 36);
        Integer.toString(22, 36);
        Integer.toString(23, 36);
        Integer.toString(24, 36);
        Integer.toString(25, 36);
        Integer.toString(26, 36);
        Integer.toString(27, 36);
        Integer.toString(28, 36);
        Integer.toString(29, 36);
        Integer.toString(30, 36);
        Integer.toString(31, 36);
        Integer.toString(32, 36);
        Integer.toString(33, 36);
        Integer.toString(34, 36);
    }

    public C1791Wa(C1701Ha c1701Ha) {
        this.a = c1701Ha.a;
        this.b = c1701Ha.b;
        this.c = c1701Ha.c;
        this.d = c1701Ha.d;
        this.e = c1701Ha.e;
        this.f = c1701Ha.f;
        this.g = c1701Ha.g;
        this.h = c1701Ha.h;
        this.i = c1701Ha.i;
        this.j = c1701Ha.j;
        this.k = c1701Ha.k;
        this.l = c1701Ha.l;
        this.m = c1701Ha.m;
        this.n = c1701Ha.n;
        this.o = c1701Ha.o;
        this.p = c1701Ha.p;
        this.q = c1701Ha.q;
        this.r = Gu.a(c1701Ha.r);
        Object[] array = c1701Ha.s.toArray();
        this.s = AbstractC2459ou.o(array.length, array);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        C1791Wa c1791Wa = (C1791Wa) obj;
        if (this.a != c1791Wa.a || this.b != c1791Wa.b || this.c != c1791Wa.c || this.d != c1791Wa.d || this.h != c1791Wa.h || this.e != c1791Wa.e || this.f != c1791Wa.f || this.g != c1791Wa.g || !this.i.equals(c1791Wa.i) || !this.j.equals(c1791Wa.j) || !this.k.equals(c1791Wa.k) || this.l != c1791Wa.l || this.m != c1791Wa.m || !this.n.equals(c1791Wa.n) || !this.o.equals(c1791Wa.o) || !this.p.equals(c1791Wa.p) || this.q != c1791Wa.q) {
            return false;
        }
        Gu gu = this.r;
        gu.getClass();
        return AbstractC2025es.s(c1791Wa.r, gu) && this.s.equals(c1791Wa.s);
    }

    public int hashCode() {
        return this.s.hashCode() + ((this.r.hashCode() + ((((this.p.hashCode() + ((((this.n.hashCode() + ((((((this.k.hashCode() + ((this.j.hashCode() + ((this.i.hashCode() + ((((((((((((((((this.a + 31) * 31) + this.b) * 31) + this.c) * 31) + this.d) * 28629151) + (this.h ? 1 : 0)) * 31) + this.e) * 31) + this.f) * 31) + (this.g ? 1 : 0)) * 31)) * 31)) * 961)) * 961) + this.l) * 31) + this.m) * 31)) * 31) + 29791) * 31)) * 961) + (this.q ? 1 : 0)) * 887503681)) * 31);
    }
}
