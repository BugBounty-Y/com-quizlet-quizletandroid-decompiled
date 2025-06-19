package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.s1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2595s1 implements InterfaceC2552r1 {
    public final long[] a;
    public final long[] b;
    public final long c;
    public final long d;
    public final int e;

    public C2595s1(long[] jArr, long[] jArr2, long j, long j2, int i) {
        this.a = jArr;
        this.b = jArr2;
        this.c = j;
        this.d = j2;
        this.e = i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final int a() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final C2078g0 b(long j) {
        long[] jArr = this.a;
        int iK = Yo.k(jArr, j, true);
        long j2 = jArr[iK];
        long[] jArr2 = this.b;
        C2166i0 c2166i0 = new C2166i0(j2, jArr2[iK]);
        if (j2 >= j || iK == jArr.length - 1) {
            return new C2078g0(c2166i0, c2166i0);
        }
        int i = iK + 1;
        return new C2078g0(c2166i0, new C2166i0(jArr[i], jArr2[i]));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final long c(long j) {
        return this.a[Yo.k(this.b, j, true)];
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final long j() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final long zza() {
        return this.c;
    }
}
