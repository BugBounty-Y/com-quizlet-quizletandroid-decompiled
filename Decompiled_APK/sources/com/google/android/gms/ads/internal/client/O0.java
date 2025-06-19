package com.google.android.gms.ads.internal.client;

/* loaded from: classes2.dex */
public final class O0 extends AbstractBinderC1621w {
    public final com.google.android.gms.ads.d a;

    public O0(com.google.android.gms.ads.d dVar) {
        this.a = dVar;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void g() {
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void h() {
        com.google.android.gms.ads.d dVar = this.a;
        if (dVar != null) {
            dVar.onAdImpression();
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void i() {
        com.google.android.gms.ads.d dVar = this.a;
        if (dVar != null) {
            dVar.onAdOpened();
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void j() {
        com.google.android.gms.ads.d dVar = this.a;
        if (dVar != null) {
            dVar.onAdClosed();
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void q() {
        com.google.android.gms.ads.d dVar = this.a;
        if (dVar != null) {
            dVar.onAdClicked();
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void r(zze zzeVar) {
        com.google.android.gms.ads.d dVar = this.a;
        if (dVar != null) {
            dVar.onAdFailedToLoad(zzeVar.b());
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void t() {
        com.google.android.gms.ads.d dVar = this.a;
        if (dVar != null) {
            dVar.onAdSwipeGestureClicked();
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void u(int i) {
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void zzi() {
        com.google.android.gms.ads.d dVar = this.a;
        if (dVar != null) {
            dVar.onAdLoaded();
        }
    }
}
