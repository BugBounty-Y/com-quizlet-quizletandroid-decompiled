package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class XD {
    public final String a;
    public int b;
    public long c;
    public final C2093gF d;
    public boolean e;
    public boolean f;
    public final /* synthetic */ YD g;

    public XD(YD yd, String str, int i, C2093gF c2093gF) {
        this.g = yd;
        this.a = str;
        this.b = i;
        this.c = c2093gF == null ? -1L : c2093gF.d;
        if (c2093gF == null || !c2093gF.b()) {
            return;
        }
        this.d = c2093gF;
    }

    public final boolean a(RD rd) {
        C2093gF c2093gF = rd.d;
        if (c2093gF == null) {
            return this.b != rd.c;
        }
        long j = this.c;
        if (j == -1) {
            return false;
        }
        long j2 = c2093gF.d;
        if (j2 > j) {
            return true;
        }
        C2093gF c2093gF2 = this.d;
        if (c2093gF2 == null) {
            return false;
        }
        A9 a9 = rd.b;
        int iA = a9.a(c2093gF.a);
        int iA2 = a9.a(c2093gF2.a);
        if (j2 < c2093gF2.d || iA < iA2) {
            return false;
        }
        if (iA > iA2) {
            return true;
        }
        boolean zB = c2093gF.b();
        int i = c2093gF2.b;
        if (!zB) {
            int i2 = c2093gF.e;
            return i2 == -1 || i2 > i;
        }
        int i3 = c2093gF.b;
        if (i3 > i) {
            return true;
        }
        if (i3 == i) {
            return c2093gF.c > c2093gF2.c;
        }
        return false;
    }

    public final boolean b(A9 a9, A9 a92) {
        C2093gF c2093gF;
        int i = this.b;
        if (i < a9.c()) {
            YD yd = this.g;
            a9.e(i, yd.a, 0L);
            C2518q9 c2518q9 = yd.a;
            for (int i2 = c2518q9.k; i2 <= c2518q9.l; i2++) {
                int iA = a92.a(a9.f(i2));
                if (iA != -1) {
                    i = a92.d(iA, yd.b, false).c;
                    break;
                }
            }
            i = -1;
        } else if (i >= a92.c()) {
            i = -1;
        }
        this.b = i;
        return i != -1 && ((c2093gF = this.d) == null || a92.a(c2093gF.a) != -1);
    }
}
