package com.google.android.gms.internal.ads;

import java.io.EOFException;
import java.io.InterruptedIOException;
import java.util.List;

/* loaded from: classes2.dex */
public final class J0 implements U {
    public C2695uF b;
    public int c;
    public int d;
    public int e;
    public C1948d1 g;
    public P h;
    public androidx.compose.foundation.gestures.l1 i;
    public F1 j;
    public final Kn a = new Kn(6);
    public long f = -1;

    public final int a(P p) {
        Kn kn = this.a;
        kn.g(2);
        p.k(kn.a, 0, 2, false);
        return kn.D();
    }

    public final void b() {
        C2695uF c2695uF = this.b;
        c2695uF.getClass();
        c2695uF.n();
        this.b.p(new Y(-9223372036854775807L, 0L));
        this.c = 6;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) throws EOFException, InterruptedIOException {
        P p = (P) v;
        if (a(p) == 65496) {
            int iA = a(p);
            this.d = iA;
            Kn kn = this.a;
            if (iA == 65504) {
                kn.g(2);
                P p2 = (P) v;
                p2.k(kn.a, 0, 2, false);
                p2.n(kn.D() - 2, false);
                iA = a(p);
                this.d = iA;
            }
            if (iA == 65505) {
                P p3 = (P) v;
                p3.n(2, false);
                kn.g(6);
                p3.k(kn.a, 0, 6, false);
                if (kn.H() == 1165519206 && kn.D() == 0) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        this.b = (C2695uF) w;
    }

    /* JADX WARN: Code restructure failed: missing block: B:80:0x0195, code lost:
    
        r10 = -9223372036854775807L;
     */
    /* JADX WARN: Removed duplicated region for block: B:104:0x0210  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x0227  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x027e  */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.V r33, androidx.compose.foundation.lazy.layout.C0429a r34) throws org.xmlpull.v1.XmlPullParserException, java.io.IOException, java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 728
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.J0.f(com.google.android.gms.internal.ads.V, androidx.compose.foundation.lazy.layout.a):int");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        if (j == 0) {
            this.c = 0;
            this.j = null;
        } else if (this.c == 5) {
            F1 f1 = this.j;
            f1.getClass();
            f1.h(j, j2);
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        C2244ju c2244ju = AbstractC2330lu.b;
        return Bu.e;
    }
}
