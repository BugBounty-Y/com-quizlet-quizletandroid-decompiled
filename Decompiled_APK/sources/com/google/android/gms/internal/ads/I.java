package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class I implements InterfaceC2122h0 {
    public final K a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;
    public final long f;

    public I(K k, long j, long j2, long j3, long j4, long j5) {
        this.a = k;
        this.b = j;
        this.c = j2;
        this.d = j3;
        this.e = j4;
        this.f = j5;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final C2078g0 b(long j) {
        C2166i0 c2166i0 = new C2166i0(j, J.a(this.a.h(j), 0L, this.c, this.d, this.e, this.f));
        return new C2078g0(c2166i0, c2166i0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final long zza() {
        return this.b;
    }
}
