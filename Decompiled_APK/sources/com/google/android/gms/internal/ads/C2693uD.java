package com.google.android.gms.internal.ads;

import android.util.Pair;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;

/* renamed from: com.google.android.gms.internal.ads.uD, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2693uD {
    public final Object a;
    public final Object b;
    public final AF[] c;
    public boolean d;
    public boolean e;
    public boolean f;
    public C2736vD g;
    public boolean h;
    public final boolean[] i;
    public final JE[] j;
    public final VF k;
    public final C2538qn l;
    public C2693uD m;
    public HF n;
    public YF o;
    public long p;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r6v3, types: [com.google.android.gms.internal.ads.PE] */
    public C2693uD(JE[] jeArr, long j, VF vf, C1963dG c1963dG, C2538qn c2538qn, C2736vD c2736vD, YF yf) {
        this.j = jeArr;
        this.p = j;
        this.k = vf;
        this.l = c2538qn;
        C2093gF c2093gF = c2736vD.a;
        this.b = c2093gF.a;
        this.g = c2736vD;
        this.n = HF.d;
        this.o = yf;
        this.c = new AF[2];
        this.i = new boolean[2];
        c2538qn.getClass();
        int i = LD.k;
        Pair pair = (Pair) c2093gF.a;
        Object obj = pair.first;
        C2093gF c2093gFA = c2093gF.a(pair.second);
        FD fd = (FD) ((HashMap) c2538qn.e).get(obj);
        fd.getClass();
        ((HashSet) c2538qn.h).add(fd);
        ED ed = (ED) ((HashMap) c2538qn.g).get(fd);
        if (ed != null) {
            ed.a.g(ed.b);
        }
        fd.c.add(c2093gFA);
        ZE zeB = fd.a.b(c2093gFA, c1963dG, c2736vD.b);
        ((IdentityHashMap) c2538qn.d).put(zeB, fd);
        c2538qn.m();
        long j2 = c2736vD.d;
        this.a = j2 != -9223372036854775807L ? new PE(zeB, j2) : zeB;
    }

    /* JADX WARN: Type inference failed for: r5v0, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    public final long a(YF yf, long j, boolean z, boolean[] zArr) {
        JE[] jeArr;
        int i = 0;
        while (true) {
            boolean z2 = true;
            if (i >= yf.a) {
                break;
            }
            if (z || !yf.a(this.o, i)) {
                z2 = false;
            }
            this.i[i] = z2;
            i++;
        }
        int i2 = 0;
        while (true) {
            jeArr = this.j;
            if (i2 >= 2) {
                break;
            }
            jeArr[i2].getClass();
            i2++;
        }
        l();
        this.o = yf;
        if (this.m == null) {
            int i3 = 0;
            while (true) {
                YF yf2 = this.o;
                if (i3 >= yf2.a) {
                    break;
                }
                yf2.b(i3);
                XF xf = ((XF[]) this.o.c)[i3];
                i3++;
            }
        }
        ?? r5 = this.a;
        XF[] xfArr = (XF[]) yf.c;
        boolean[] zArr2 = this.i;
        AF[] afArr = this.c;
        long jM = r5.m(xfArr, zArr2, afArr, zArr, j);
        for (int i4 = 0; i4 < 2; i4++) {
            jeArr[i4].getClass();
        }
        this.f = false;
        for (int i5 = 0; i5 < 2; i5++) {
            if (afArr[i5] != null) {
                AbstractC1795We.L(yf.b(i5));
                jeArr[i5].getClass();
                this.f = true;
            } else {
                AbstractC1795We.L(xfArr[i5] == null);
            }
        }
        return jM;
    }

    /* JADX WARN: Type inference failed for: r0v5, types: [com.google.android.gms.internal.ads.BF, java.lang.Object] */
    public final long b() {
        if (!this.e) {
            return this.g.b;
        }
        long jB = this.f ? this.a.b() : Long.MIN_VALUE;
        return jB == Long.MIN_VALUE ? this.g.e : jB;
    }

    public final long c() {
        return this.g.b + this.p;
    }

    public final C2693uD d() {
        return this.m;
    }

    public final HF e() {
        return this.n;
    }

    public final YF f() {
        return this.o;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:104:0x0257  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x03be  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.YF g(com.google.android.gms.internal.ads.A9 r34) {
        /*
            Method dump skipped, instructions count: 2258
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2693uD.g(com.google.android.gms.internal.ads.A9):com.google.android.gms.internal.ads.YF");
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    public final void h(A9 a9) {
        this.e = true;
        this.n = this.a.h();
        YF yfG = g(a9);
        C2736vD c2736vD = this.g;
        long j = c2736vD.e;
        long jMax = c2736vD.b;
        if (j != -9223372036854775807L && jMax >= j) {
            jMax = Math.max(0L, j - 1);
        }
        long jA = a(yfG, jMax, false, new boolean[2]);
        long j2 = this.p;
        C2736vD c2736vD2 = this.g;
        this.p = (c2736vD2.b - jA) + j2;
        this.g = c2736vD2.b(jA);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    public final void i() {
        l();
        ?? r0 = this.a;
        try {
            boolean z = r0 instanceof PE;
            C2538qn c2538qn = this.l;
            if (z) {
                c2538qn.f(((PE) r0).a);
            } else {
                c2538qn.f(r0);
            }
        } catch (RuntimeException e) {
            AbstractC2096gb.A("MediaPeriodHolder", "Period release failed.", e);
        }
    }

    /* JADX WARN: Type inference failed for: r0v4, types: [com.google.android.gms.internal.ads.BF, java.lang.Object] */
    public final boolean j() {
        if (this.e) {
            return !this.f || this.a.b() == Long.MIN_VALUE;
        }
        return false;
    }

    public final boolean k() {
        if (this.e) {
            return j() || b() - this.g.b >= -9223372036854775807L;
        }
        return false;
    }

    public final void l() {
        if (this.m != null) {
            return;
        }
        int i = 0;
        while (true) {
            YF yf = this.o;
            if (i >= yf.a) {
                return;
            }
            yf.b(i);
            XF xf = ((XF[]) this.o.c)[i];
            i++;
        }
    }
}
