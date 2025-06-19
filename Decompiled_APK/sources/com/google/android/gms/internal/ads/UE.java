package com.google.android.gms.internal.ads;

import java.util.List;

/* loaded from: classes2.dex */
public final class UE implements BF {
    public final BF a;
    public final AbstractC2330lu b;

    public UE(BF bf, List list) {
        this.a = bf;
        this.b = AbstractC2330lu.n(list);
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long a() {
        return this.a.a();
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long b() {
        return this.a.b();
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final void d(long j) {
        this.a.d(j);
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean k(C2607sD c2607sD) {
        return this.a.k(c2607sD);
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean o() {
        return this.a.o();
    }
}
