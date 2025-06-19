package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.n1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2381n1 implements InterfaceC2552r1, InterfaceC2122h0 {
    public final long a;
    public final long b;
    public final int c;
    public final long d;
    public final int e;
    public final long f;
    public final long g;
    public final int h;
    public final int i;
    public final long j;

    public C2381n1(int i, int i2, long j, long j2) {
        long jMax;
        this.a = j;
        this.b = j2;
        this.c = i2 == -1 ? 1 : i2;
        this.e = i;
        if (j == -1) {
            this.d = -1L;
            jMax = -9223372036854775807L;
        } else {
            long j3 = j - j2;
            this.d = j3;
            jMax = (Math.max(0L, j3) * 8000000) / i;
        }
        this.f = jMax;
        this.g = j2;
        this.h = i;
        this.i = i2;
        this.j = j == -1 ? -1L : j;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final int a() {
        return this.h;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final C2078g0 b(long j) {
        long j2 = this.d;
        long j3 = this.b;
        if (j2 == -1) {
            C2166i0 c2166i0 = new C2166i0(0L, j3);
            return new C2078g0(c2166i0, c2166i0);
        }
        int i = this.e;
        long j4 = this.c;
        long jMin = (((i * j) / 8000000) / j4) * j4;
        if (j2 != -1) {
            jMin = Math.min(jMin, j2 - j4);
        }
        long jMax = Math.max(jMin, 0L) + j3;
        long jMax2 = (Math.max(0L, jMax - j3) * 8000000) / i;
        C2166i0 c2166i02 = new C2166i0(jMax2, jMax);
        if (j2 != -1 && jMax2 < j) {
            long j5 = jMax + j4;
            if (j5 < this.a) {
                return new C2078g0(c2166i02, new C2166i0((Math.max(0L, j5 - j3) * 8000000) / i, j5));
            }
        }
        return new C2078g0(c2166i02, c2166i02);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final long c(long j) {
        return (Math.max(0L, j - this.b) * 8000000) / this.e;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        return this.d != -1;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final long j() {
        return this.j;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final long zza() {
        return this.f;
    }
}
