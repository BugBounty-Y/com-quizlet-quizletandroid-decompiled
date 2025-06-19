package com.google.android.gms.internal.ads;

import androidx.compose.ui.text.input.C1007j;
import java.math.RoundingMode;

/* renamed from: com.google.android.gms.internal.ads.p3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2469p3 implements InterfaceC2122h0 {
    public final C1007j a;
    public final int b;
    public final long c;
    public final long d;
    public final long e;

    public C2469p3(C1007j c1007j, int i, long j, long j2) {
        this.a = c1007j;
        this.b = i;
        this.c = j;
        long j3 = (j2 - j) / c1007j.d;
        this.d = j3;
        this.e = d(j3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final C2078g0 b(long j) {
        long j2 = this.b;
        C1007j c1007j = this.a;
        long j3 = (c1007j.c * j) / (j2 * 1000000);
        String str = Yo.a;
        long j4 = this.d - 1;
        long jMax = Math.max(0L, Math.min(j3, j4));
        long j5 = c1007j.d;
        long jD = d(jMax);
        long j6 = this.c;
        C2166i0 c2166i0 = new C2166i0(jD, (jMax * j5) + j6);
        if (jD >= j || jMax == j4) {
            return new C2078g0(c2166i0, c2166i0);
        }
        long j7 = jMax + 1;
        return new C2078g0(c2166i0, new C2166i0(d(j7), (j5 * j7) + j6));
    }

    public final long d(long j) {
        return Yo.v(j * this.b, 1000000L, this.a.c, RoundingMode.DOWN);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final long zza() {
        return this.e;
    }
}
