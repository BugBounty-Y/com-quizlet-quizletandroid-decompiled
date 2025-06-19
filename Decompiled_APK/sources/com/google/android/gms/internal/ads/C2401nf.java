package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.nf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2401nf implements CC {
    public final /* synthetic */ int a;
    public final C1729Le b;

    public /* synthetic */ C2401nf(C1729Le c1729Le, int i) {
        this.a = i;
        this.b = c1729Le;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final /* bridge */ /* synthetic */ Object zzb() {
        switch (this.a) {
            case 0:
                return new C2358mf(this.b.a(), 0);
            default:
                return new C2358mf(this.b.a(), 1);
        }
    }
}
