package com.google.android.gms.internal.ads;

import java.math.RoundingMode;

/* renamed from: com.google.android.gms.internal.ads.w0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2766w0 {
    public final C2723v0 a;
    public final InterfaceC2380n0 b;
    public final int c;
    public final int d;
    public final long e;
    public int f;
    public int g;
    public int h;
    public int i;
    public int j;
    public int k;
    public long l;
    public long[] m;
    public int[] n;

    public C2766w0(int i, C2723v0 c2723v0, InterfaceC2380n0 interfaceC2380n0) {
        this.a = c2723v0;
        int iA = c2723v0.a();
        boolean z = true;
        if (iA != 1) {
            if (iA == 2) {
                iA = 2;
            } else {
                z = false;
            }
        }
        AbstractC1795We.B(z);
        int i2 = ((i / 10) + 48) | (((i % 10) + 48) << 8);
        this.c = (iA == 2 ? 1667497984 : 1651965952) | i2;
        long j = c2723v0.c;
        RoundingMode roundingMode = RoundingMode.DOWN;
        int i3 = c2723v0.d;
        this.e = Yo.v(i3, c2723v0.b * 1000000, j, roundingMode);
        this.b = interfaceC2380n0;
        this.d = iA == 2 ? 1650720768 | i2 : -1;
        this.l = -1L;
        this.m = new long[com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH];
        this.n = new int[com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH];
        this.f = i3;
    }

    public final C2078g0 a(long j) {
        if (this.k == 0) {
            C2166i0 c2166i0 = new C2166i0(0L, this.l);
            return new C2078g0(c2166i0, c2166i0);
        }
        int i = (int) (j / ((this.e * 1) / this.f));
        int iJ = Yo.j(this.n, i, true, true);
        if (this.n[iJ] == i) {
            C2166i0 c2166i0B = b(iJ);
            return new C2078g0(c2166i0B, c2166i0B);
        }
        C2166i0 c2166i0B2 = b(iJ);
        int i2 = iJ + 1;
        return i2 < this.m.length ? new C2078g0(c2166i0B2, b(i2)) : new C2078g0(c2166i0B2, c2166i0B2);
    }

    public final C2166i0 b(int i) {
        return new C2166i0(((this.e * 1) / this.f) * this.n[i], this.m[i]);
    }
}
