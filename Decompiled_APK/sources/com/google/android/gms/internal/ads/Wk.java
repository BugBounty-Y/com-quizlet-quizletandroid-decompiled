package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class Wk extends AbstractBinderC2527qc {
    public final /* synthetic */ Xk a;

    public Wk(Xk xk) {
        this.a = xk;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void f() {
        Xk xk = this.a;
        S4 s4 = xk.b;
        C2084g6 c2084g6 = new C2084g6("rewarded");
        c2084g6.a = Long.valueOf(xk.a);
        c2084g6.c = "onAdImpression";
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void h() {
        Xk xk = this.a;
        S4 s4 = xk.b;
        C2084g6 c2084g6 = new C2084g6("rewarded");
        c2084g6.a = Long.valueOf(xk.a);
        c2084g6.c = "onRewardedAdClosed";
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void h3(zze zzeVar) {
        Xk xk = this.a;
        S4 s4 = xk.b;
        int i = zzeVar.a;
        C2084g6 c2084g6 = new C2084g6("rewarded");
        c2084g6.a = Long.valueOf(xk.a);
        c2084g6.c = "onRewardedAdFailedToShow";
        c2084g6.d = Integer.valueOf(i);
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void i() {
        Xk xk = this.a;
        S4 s4 = xk.b;
        C2084g6 c2084g6 = new C2084g6("rewarded");
        c2084g6.a = Long.valueOf(xk.a);
        c2084g6.c = "onRewardedAdOpened";
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void k0(int i) {
        Xk xk = this.a;
        S4 s4 = xk.b;
        C2084g6 c2084g6 = new C2084g6("rewarded");
        c2084g6.a = Long.valueOf(xk.a);
        c2084g6.c = "onRewardedAdFailedToShow";
        c2084g6.d = Integer.valueOf(i);
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void q0(InterfaceC2312lc interfaceC2312lc) {
        Xk xk = this.a;
        S4 s4 = xk.b;
        C2084g6 c2084g6 = new C2084g6("rewarded");
        c2084g6.a = Long.valueOf(xk.a);
        c2084g6.c = "onUserEarnedReward";
        c2084g6.e = interfaceC2312lc.f();
        c2084g6.f = Integer.valueOf(interfaceC2312lc.zze());
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2569rc
    public final void zze() {
        Xk xk = this.a;
        S4 s4 = xk.b;
        C2084g6 c2084g6 = new C2084g6("rewarded");
        c2084g6.a = Long.valueOf(xk.a);
        c2084g6.c = "onAdClicked";
        s4.k(c2084g6);
    }
}
