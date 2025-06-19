package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Pi implements CC {
    public final /* synthetic */ int a;
    public final C1969df b;

    public /* synthetic */ Pi(C1969df c1969df, int i) {
        this.a = i;
        this.b = c1969df;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return new Oi(this.b.a());
            default:
                return new C2017ek(this.b.a());
        }
    }
}
