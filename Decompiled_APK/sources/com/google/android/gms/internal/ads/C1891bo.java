package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.bo, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1891bo implements Vo {
    public final C2227jd a;
    public final C2023eq b;
    public final int c;

    public C1891bo(C2227jd c2227jd, C2023eq c2023eq, int i) {
        this.a = c2227jd;
        this.b = c2023eq;
        this.c = i;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        return 5;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        return this.a.d(new Q4(this, 8));
    }
}
