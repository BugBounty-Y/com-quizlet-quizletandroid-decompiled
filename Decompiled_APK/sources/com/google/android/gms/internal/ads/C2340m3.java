package com.google.android.gms.internal.ads;

import androidx.compose.ui.text.input.C1007j;
import java.math.RoundingMode;

/* renamed from: com.google.android.gms.internal.ads.m3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2340m3 implements InterfaceC2297l3 {
    public final C2695uF a;
    public final InterfaceC2380n0 b;
    public final C1007j c;
    public final C1832aG d;
    public final int e;
    public long f;
    public int g;
    public long h;

    public C2340m3(C2695uF c2695uF, InterfaceC2380n0 interfaceC2380n0, C1007j c1007j, String str, int i) throws zzaz {
        this.a = c2695uF;
        this.b = interfaceC2380n0;
        this.c = c1007j;
        int i2 = c1007j.e;
        int i3 = c1007j.b;
        int i4 = (i2 * i3) / 8;
        int i5 = c1007j.d;
        if (i5 != i4) {
            throw zzaz.a(null, "Expected block size: " + i4 + "; got: " + i5);
        }
        int i6 = c1007j.c;
        int i7 = i6 * i4;
        int i8 = i7 * 8;
        int iMax = Math.max(i4, i7 / 10);
        this.e = iMax;
        EF ef = new EF();
        ef.a("audio/wav");
        ef.d(str);
        ef.g = i8;
        ef.h = i8;
        ef.m = iMax;
        ef.B = i3;
        ef.C = i6;
        ef.D = i;
        this.d = new C1832aG(ef);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2297l3
    public final void a(long j) {
        this.f = j;
        this.g = 0;
        this.h = 0L;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2297l3
    public final void e(int i, long j) {
        this.a.p(new C2469p3(this.c, 1, i, j));
        this.b.a(this.d);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2297l3
    public final boolean f(P p, long j) {
        int i;
        int i2;
        long j2 = j;
        while (j2 > 0 && (i = this.g) < (i2 = this.e)) {
            int iD = this.b.d(p, (int) Math.min(i2 - i, j2), true);
            if (iD == -1) {
                j2 = 0;
            } else {
                this.g += iD;
                j2 -= iD;
            }
        }
        int i3 = this.g;
        int i4 = this.c.d;
        int i5 = i3 / i4;
        if (i5 > 0) {
            long jV = this.f + Yo.v(this.h, 1000000L, r2.c, RoundingMode.DOWN);
            int i6 = i5 * i4;
            int i7 = this.g - i6;
            this.b.f(jV, 1, i6, i7, null);
            this.h += i5;
            this.g = i7;
        }
        return j2 <= 0;
    }
}
