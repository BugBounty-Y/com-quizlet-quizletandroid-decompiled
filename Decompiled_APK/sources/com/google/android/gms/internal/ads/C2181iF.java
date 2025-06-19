package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.iF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2181iF implements InterfaceC2491pj {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2866yE b;
    public final /* synthetic */ YE c;
    public final /* synthetic */ androidx.compose.animation.core.S0 d;

    public /* synthetic */ C2181iF(C2866yE c2866yE, YE ye, androidx.compose.animation.core.S0 s0, int i) {
        this.a = i;
        this.b = c2866yE;
        this.c = ye;
        this.d = s0;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2491pj, com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public final void mo10b(Object obj) {
        switch (this.a) {
            case 0:
                ((InterfaceC2266kF) obj).c(0, this.b.a, this.c, this.d);
                break;
            default:
                ((InterfaceC2266kF) obj).e(0, this.b.a, this.c, this.d);
                break;
        }
    }
}
