package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class Vk extends AbstractBinderC2698uc {
    public final /* synthetic */ Xk a;

    public Vk(Xk xk) {
        this.a = xk;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void h() {
        Xk xk = this.a;
        S4 s4 = xk.b;
        C2084g6 c2084g6 = new C2084g6("rewarded");
        c2084g6.a = Long.valueOf(xk.a);
        c2084g6.c = "onRewardedAdLoaded";
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void r(zze zzeVar) {
        Xk xk = this.a;
        S4 s4 = xk.b;
        int i = zzeVar.a;
        C2084g6 c2084g6 = new C2084g6("rewarded");
        c2084g6.a = Long.valueOf(xk.a);
        c2084g6.c = "onRewardedAdFailedToLoad";
        c2084g6.d = Integer.valueOf(i);
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void u(int i) {
        Xk xk = this.a;
        S4 s4 = xk.b;
        C2084g6 c2084g6 = new C2084g6("rewarded");
        c2084g6.a = Long.valueOf(xk.a);
        c2084g6.c = "onRewardedAdFailedToLoad";
        c2084g6.d = Integer.valueOf(i);
        s4.k(c2084g6);
    }
}
