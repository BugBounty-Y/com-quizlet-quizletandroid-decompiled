package com.google.android.gms.internal.ads;

import android.util.Pair;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.tagmanager.ModuleDescriptor;

/* loaded from: classes2.dex */
public abstract class A9 {
    public static final X8 a = new X8();

    static {
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
        Integer.toString(2, 36);
    }

    public abstract int a(Object obj);

    public abstract int b();

    public abstract int c();

    public abstract C2303l9 d(int i, C2303l9 c2303l9, boolean z);

    public abstract C2518q9 e(int i, C2518q9 c2518q9, long j);

    public final boolean equals(Object obj) {
        int iH;
        if (this != obj) {
            if (obj instanceof A9) {
                A9 a9 = (A9) obj;
                if (a9.c() == c() && a9.b() == b()) {
                    C2518q9 c2518q9 = new C2518q9();
                    C2303l9 c2303l9 = new C2303l9();
                    C2518q9 c2518q92 = new C2518q9();
                    C2303l9 c2303l92 = new C2303l9();
                    int i = 0;
                    while (true) {
                        if (i >= c()) {
                            int i2 = 0;
                            while (true) {
                                if (i2 >= b()) {
                                    int iG = g(true);
                                    if (iG == a9.g(true) && (iH = h(true)) == a9.h(true)) {
                                        while (iG != iH) {
                                            int iJ = j(iG, 0, true);
                                            if (iJ == a9.j(iG, 0, true)) {
                                                iG = iJ;
                                            }
                                        }
                                    }
                                } else {
                                    if (!d(i2, c2303l9, true).equals(a9.d(i2, c2303l92, true))) {
                                        break;
                                    }
                                    i2++;
                                }
                            }
                        } else {
                            if (!e(i, c2518q9, 0L).equals(a9.e(i, c2518q92, 0L))) {
                                break;
                            }
                            i++;
                        }
                    }
                }
            }
            return false;
        }
        return true;
    }

    public abstract Object f(int i);

    public int g(boolean z) {
        return o() ? -1 : 0;
    }

    public int h(boolean z) {
        if (o()) {
            return -1;
        }
        return c() - 1;
    }

    public final int hashCode() {
        int i;
        C2518q9 c2518q9 = new C2518q9();
        C2303l9 c2303l9 = new C2303l9();
        int iC = c() + ModuleDescriptor.MODULE_VERSION;
        int i2 = 0;
        while (true) {
            i = iC * 31;
            if (i2 >= c()) {
                break;
            }
            iC = i + e(i2, c2518q9, 0L).hashCode();
            i2++;
        }
        int iB = b() + i;
        for (int i3 = 0; i3 < b(); i3++) {
            iB = (iB * 31) + d(i3, c2303l9, true).hashCode();
        }
        int iG = g(true);
        while (iG != -1) {
            iB = (iB * 31) + iG;
            iG = j(iG, 0, true);
        }
        return iB;
    }

    public final int i(int i, C2303l9 c2303l9, C2518q9 c2518q9, int i2, boolean z) {
        int i3 = d(i, c2303l9, false).c;
        if (e(i3, c2518q9, 0L).l != i) {
            return i + 1;
        }
        int iJ = j(i3, i2, z);
        if (iJ == -1) {
            return -1;
        }
        return e(iJ, c2518q9, 0L).k;
    }

    public int j(int i, int i2, boolean z) {
        if (i2 == 0) {
            if (i == h(z)) {
                return -1;
            }
            return i + 1;
        }
        if (i2 == 1) {
            return i;
        }
        if (i2 == 2) {
            return i == h(z) ? g(z) : i + 1;
        }
        throw new IllegalStateException();
    }

    public int k(int i) {
        if (i == g(false)) {
            return -1;
        }
        return i - 1;
    }

    public final Pair l(C2518q9 c2518q9, C2303l9 c2303l9, int i, long j) {
        Pair pairM = m(c2518q9, c2303l9, i, j, 0L);
        pairM.getClass();
        return pairM;
    }

    public final Pair m(C2518q9 c2518q9, C2303l9 c2303l9, int i, long j, long j2) {
        AbstractC1795We.f(i, c());
        e(i, c2518q9, j2);
        if (j == -9223372036854775807L) {
            c2518q9.getClass();
            j = 0;
        }
        int i2 = c2518q9.k;
        d(i2, c2303l9, false);
        while (i2 < c2518q9.l) {
            c2303l9.getClass();
            if (j == 0) {
                break;
            }
            int i3 = i2 + 1;
            d(i3, c2303l9, false).getClass();
            if (j < 0) {
                break;
            }
            i2 = i3;
        }
        d(i2, c2303l9, true);
        c2303l9.getClass();
        long j3 = c2303l9.d;
        if (j3 != -9223372036854775807L) {
            j = Math.min(j, j3 - 1);
        }
        long jMax = Math.max(0L, j);
        Object obj = c2303l9.b;
        obj.getClass();
        return Pair.create(obj, Long.valueOf(jMax));
    }

    public C2303l9 n(Object obj, C2303l9 c2303l9) {
        return d(a(obj), c2303l9, true);
    }

    public final boolean o() {
        return c() == 0;
    }
}
