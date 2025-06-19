package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class Fr extends AbstractBinderC2698uc {
    public final /* synthetic */ C1985dw a;
    public final /* synthetic */ Sp b;
    public final /* synthetic */ C2670tr c;

    public Fr(C2670tr c2670tr, C1985dw c1985dw, Sp sp) {
        this.a = c1985dw;
        this.b = sp;
        this.c = c2670tr;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void h() {
        this.a.g(this.b);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void r(zze zzeVar) {
        String string = zzeVar.b().toString();
        C2670tr c2670tr = this.c;
        com.google.android.gms.ads.internal.util.client.i.h("Failed to load rewarded ad with error: " + string + ", adUnitId: " + c2670tr.e.a);
        C2670tr.i(c2670tr, zzeVar);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void u(int i) {
    }
}
