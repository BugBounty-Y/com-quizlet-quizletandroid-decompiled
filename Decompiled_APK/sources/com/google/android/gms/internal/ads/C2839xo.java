package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.xo, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2839xo implements Vo {
    public final /* synthetic */ int a;
    public final C2227jd b;

    public /* synthetic */ C2839xo(C2227jd c2227jd, int i) {
        this.a = i;
        this.b = c2227jd;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        switch (this.a) {
            case 0:
                return 55;
            case 1:
                return 20;
            case 2:
                return 24;
            case 3:
                return 45;
            default:
                return 51;
        }
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        switch (this.a) {
            case 0:
                return this.b.d(new CallableC2516q7(1));
            case 1:
                return this.b.d(new CallableC2516q7(2));
            case 2:
                return this.b.d(new CallableC2516q7(3));
            case 3:
                return this.b.d(new CallableC2516q7(4));
            default:
                return this.b.d(new CallableC2516q7(5));
        }
    }
}
