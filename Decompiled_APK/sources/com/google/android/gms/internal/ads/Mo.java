package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Mo implements Vo {
    public final String a;
    public final int b;

    public Mo(String str, int i) {
        this.a = str;
        this.b = i;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        return 31;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        return AbstractC2025es.E(new C2453oo(this.a, this.b, 1));
    }
}
