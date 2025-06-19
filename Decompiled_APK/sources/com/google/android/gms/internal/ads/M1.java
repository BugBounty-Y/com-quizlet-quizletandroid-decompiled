package com.google.android.gms.internal.ads;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public final class M1 implements InterfaceC2122h0 {
    public final /* synthetic */ N1 a;

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final C2078g0 b(long j) {
        N1 n1 = this.a;
        BigInteger bigIntegerValueOf = BigInteger.valueOf((n1.d.i * j) / 1000000);
        long j2 = n1.c;
        long j3 = n1.b;
        long jLongValue = bigIntegerValueOf.multiply(BigInteger.valueOf(j2 - j3)).divide(BigInteger.valueOf(n1.f)).longValue() + j3;
        String str = Yo.a;
        C2166i0 c2166i0 = new C2166i0(j, Math.max(j3, Math.min(jLongValue - 30000, j2 - 1)));
        return new C2078g0(c2166i0, c2166i0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final long zza() {
        N1 n1 = this.a;
        U1 u1 = n1.d;
        return (n1.f * 1000000) / u1.i;
    }
}
