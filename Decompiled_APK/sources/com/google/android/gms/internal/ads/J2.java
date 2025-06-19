package com.google.android.gms.internal.ads;

import androidx.compose.foundation.lazy.layout.C0429a;
import androidx.compose.material3.C0591b1;
import java.io.EOFException;
import java.io.InterruptedIOException;
import java.util.List;

/* loaded from: classes2.dex */
public final class J2 implements U {
    public final Kn c;
    public final C2466p0 d;
    public C2695uF e;
    public long f;
    public boolean h;
    public boolean i;
    public final K2 a = new K2(null, 0, "audio/mp4a-latm", true);
    public final Kn b = new Kn(2048);
    public long g = -1;

    public J2() {
        Kn kn = new Kn(10);
        this.c = kn;
        byte[] bArr = kn.a;
        this.d = new C2466p0(bArr.length, bArr);
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) throws EOFException, InterruptedIOException {
        Kn kn;
        P p;
        int i = 0;
        while (true) {
            kn = this.c;
            p = (P) v;
            p.k(kn.a, 0, 10, false);
            kn.j(0);
            if (kn.B() != 4801587) {
                break;
            }
            kn.k(3);
            int iY = kn.y();
            i += iY + 10;
            p.n(iY, false);
        }
        P p2 = (P) v;
        p2.f = 0;
        p.n(i, false);
        if (this.g == -1) {
            this.g = i;
        }
        int i2 = 0;
        int i3 = 0;
        int i4 = i;
        do {
            p.k(kn.a, 0, 2, false);
            kn.j(0);
            if ((kn.D() & 65526) == 65520) {
                i2++;
                if (i2 >= 4 && i3 > 188) {
                    return true;
                }
                p.k(kn.a, 0, 4, false);
                C2466p0 c2466p0 = this.d;
                c2466p0.s(14);
                int iF = c2466p0.f(13);
                if (iF <= 6) {
                    i4++;
                    p2.f = 0;
                    p.n(i4, false);
                } else {
                    p.n(iF - 6, false);
                    i3 += iF;
                }
            } else {
                i4++;
                p2.f = 0;
                p.n(i4, false);
            }
            i2 = 0;
            i3 = 0;
        } while (i4 - i < 8192);
        return false;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        this.e = (C2695uF) w;
        this.a.e(w, new C0591b1(Integer.MIN_VALUE, 0, 1));
        ((C2695uF) w).n();
    }

    @Override // com.google.android.gms.internal.ads.U
    public final int f(V v, C0429a c0429a) throws EOFException, InterruptedIOException {
        AbstractC1795We.p(this.e);
        Kn kn = this.b;
        int iD = ((P) v).d(0, kn.a, 2048);
        if (!this.i) {
            this.e.p(new Y(-9223372036854775807L, 0L));
            this.i = true;
        }
        if (iD == -1) {
            return -1;
        }
        kn.j(0);
        kn.i(iD);
        boolean z = this.h;
        K2 k2 = this.a;
        if (!z) {
            k2.u = this.f;
            this.h = true;
        }
        k2.d(kn);
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        this.h = false;
        this.a.zze();
        this.f = j2;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        C2244ju c2244ju = AbstractC2330lu.b;
        return Bu.e;
    }
}
