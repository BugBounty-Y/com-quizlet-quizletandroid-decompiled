package com.google.android.gms.internal.ads;

import java.io.EOFException;
import java.io.InterruptedIOException;
import java.util.List;

/* loaded from: classes2.dex */
public final class F0 implements U {
    public final Kn a = new Kn(4);
    public final Kn b = new Kn(9);
    public final Kn c = new Kn(11);
    public final Kn d = new Kn();
    public final G0 e;
    public C2695uF f;
    public int g;
    public boolean h;
    public long i;
    public int j;
    public int k;
    public int l;
    public long m;
    public boolean n;
    public E0 o;
    public H0 p;

    public F0() {
        G0 g0 = new G0(new T());
        g0.c = -9223372036854775807L;
        g0.d = new long[0];
        g0.e = new long[0];
        this.e = g0;
        this.g = 1;
    }

    public final Kn a(P p) throws EOFException, InterruptedIOException {
        int i = this.l;
        Kn kn = this.d;
        byte[] bArr = kn.a;
        if (i > bArr.length) {
            int length = bArr.length;
            kn.h(0, new byte[Math.max(length + length, i)]);
        } else {
            kn.j(0);
        }
        kn.i(this.l);
        p.h(kn.a, 0, this.l, false);
        return kn;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) throws EOFException, InterruptedIOException {
        Kn kn = this.a;
        P p = (P) v;
        p.k(kn.a, 0, 3, false);
        kn.j(0);
        if (kn.B() == 4607062) {
            p.k(kn.a, 0, 2, false);
            kn.j(0);
            if ((kn.D() & 250) == 0) {
                p.k(kn.a, 0, 4, false);
                kn.j(0);
                int iU = kn.u();
                ((P) v).f = 0;
                p.n(iU, false);
                p.k(kn.a, 0, 4, false);
                kn.j(0);
                if (kn.u() == 0) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        this.f = (C2695uF) w;
    }

    /* JADX WARN: Removed duplicated region for block: B:103:0x028d  */
    /* JADX WARN: Removed duplicated region for block: B:149:0x0393 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:152:0x039d  */
    /* JADX WARN: Removed duplicated region for block: B:153:0x03a1  */
    /* JADX WARN: Removed duplicated region for block: B:185:0x03ac A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:195:0x0007 A[SYNTHETIC] */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.V r31, androidx.compose.foundation.lazy.layout.C0429a r32) throws com.google.android.gms.internal.ads.zzaz, java.io.EOFException, java.io.InterruptedIOException {
        /*
            Method dump skipped, instructions count: 1116
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.F0.f(com.google.android.gms.internal.ads.V, androidx.compose.foundation.lazy.layout.a):int");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        if (j == 0) {
            this.g = 1;
            this.h = false;
        } else {
            this.g = 3;
        }
        this.j = 0;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        C2244ju c2244ju = AbstractC2330lu.b;
        return Bu.e;
    }
}
