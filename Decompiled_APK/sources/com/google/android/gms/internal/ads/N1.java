package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class N1 implements S1 {
    public final R1 a;
    public final long b;
    public final long c;
    public final U1 d;
    public int e;
    public long f;
    public long g;
    public long h;
    public long i;
    public long j;
    public long k;
    public long l;

    public N1(U1 u1, long j, long j2, long j3, long j4, boolean z) {
        AbstractC1795We.B(j >= 0 && j2 > j);
        this.d = u1;
        this.b = j;
        this.c = j2;
        if (j3 == j2 - j || z) {
            this.f = j4;
            this.e = 4;
        } else {
            this.e = 0;
        }
        this.a = new R1();
    }

    @Override // com.google.android.gms.internal.ads.S1
    public final void b(long j) {
        long j2 = this.f - 1;
        String str = Yo.a;
        this.h = Math.max(0L, Math.min(j, j2));
        this.e = 2;
        this.i = this.b;
        this.j = this.c;
        this.k = 0L;
        this.l = this.f;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:12:0x002b  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00b9 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00ba  */
    /* JADX WARN: Type inference failed for: r4v0 */
    /* JADX WARN: Type inference failed for: r4v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r4v5 */
    @Override // com.google.android.gms.internal.ads.S1
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long j(com.google.android.gms.internal.ads.P r24) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 343
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.N1.j(com.google.android.gms.internal.ads.P):long");
    }

    @Override // com.google.android.gms.internal.ads.S1
    public final /* bridge */ /* synthetic */ InterfaceC2122h0 zze() {
        if (this.f != 0) {
            return new M1(this);
        }
        return null;
    }
}
