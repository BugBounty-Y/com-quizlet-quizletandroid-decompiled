package com.google.android.gms.internal.ads;

import android.util.Pair;

/* renamed from: com.google.android.gms.internal.ads.o1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2424o1 implements InterfaceC2552r1 {
    public final long[] a;
    public final long[] b;
    public final long c;

    public C2424o1(long j, long[] jArr, long[] jArr2) {
        this.a = jArr;
        this.b = jArr2;
        this.c = j == -9223372036854775807L ? Yo.t(jArr2[jArr2.length - 1]) : j;
    }

    public static Pair d(long j, long[] jArr, long[] jArr2) {
        int iK = Yo.k(jArr, j, true);
        long j2 = jArr[iK];
        long j3 = jArr2[iK];
        int i = iK + 1;
        if (i == jArr.length) {
            return Pair.create(Long.valueOf(j2), Long.valueOf(j3));
        }
        return Pair.create(Long.valueOf(j), Long.valueOf(((long) ((jArr[i] == j2 ? 0.0d : (j - j2) / (r6 - j2)) * (jArr2[i] - j3))) + j3));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final int a() {
        return -2147483647;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final C2078g0 b(long j) {
        String str = Yo.a;
        Pair pairD = d(Yo.w(Math.max(0L, Math.min(j, this.c))), this.b, this.a);
        C2166i0 c2166i0 = new C2166i0(Yo.t(((Long) pairD.first).longValue()), ((Long) pairD.second).longValue());
        return new C2078g0(c2166i0, c2166i0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final long c(long j) {
        return Yo.t(((Long) d(j, this.a, this.b).second).longValue());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final long j() {
        return -1L;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final long zza() {
        return this.c;
    }
}
