package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.xj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2834xj implements CC {
    public final /* synthetic */ int a;
    public final C2326lq b;

    public /* synthetic */ C2834xj(C2326lq c2326lq, int i) {
        this.a = i;
        this.b = c2326lq;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return (C1683Ea) this.b.d;
            case 1:
                return (C1689Fa) this.b.c;
            default:
                return (InterfaceC1707Ia) this.b.b;
        }
    }
}
