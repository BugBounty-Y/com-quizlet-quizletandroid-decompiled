package com.google.android.gms.internal.ads;

import android.os.Parcel;
import com.amazon.device.ads.DTBAdSize;
import com.google.android.gms.ads.internal.client.AbstractBinderC1621w;
import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class Tk extends AbstractBinderC1621w {
    public final /* synthetic */ S4 a;
    public final /* synthetic */ Uk b;

    public Tk(Uk uk, S4 s4) {
        this.a = s4;
        this.b = uk;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void g() {
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void h() {
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void i() {
        long j = this.b.a;
        S4 s4 = this.a;
        C2084g6 c2084g6 = new C2084g6(DTBAdSize.AAX_INTERSTITIAL_AD_SIZE);
        c2084g6.a = Long.valueOf(j);
        c2084g6.c = "onAdOpened";
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void j() {
        long j = this.b.a;
        S4 s4 = this.a;
        C2084g6 c2084g6 = new C2084g6(DTBAdSize.AAX_INTERSTITIAL_AD_SIZE);
        c2084g6.a = Long.valueOf(j);
        c2084g6.c = "onAdClosed";
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void q() {
        long j = this.b.a;
        S4 s4 = this.a;
        C2084g6 c2084g6 = new C2084g6(DTBAdSize.AAX_INTERSTITIAL_AD_SIZE);
        c2084g6.a = Long.valueOf(j);
        c2084g6.c = "onAdClicked";
        String strC = C2084g6.c(c2084g6);
        C2904z9 c2904z9 = (C2904z9) s4.b;
        Parcel parcelF3 = c2904z9.f3();
        parcelF3.writeString(strC);
        c2904z9.d4(1, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void r(zze zzeVar) {
        long j = this.b.a;
        int i = zzeVar.a;
        S4 s4 = this.a;
        C2084g6 c2084g6 = new C2084g6(DTBAdSize.AAX_INTERSTITIAL_AD_SIZE);
        c2084g6.a = Long.valueOf(j);
        c2084g6.c = "onAdFailedToLoad";
        c2084g6.d = Integer.valueOf(i);
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void t() {
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void u(int i) {
        long j = this.b.a;
        S4 s4 = this.a;
        C2084g6 c2084g6 = new C2084g6(DTBAdSize.AAX_INTERSTITIAL_AD_SIZE);
        c2084g6.a = Long.valueOf(j);
        c2084g6.c = "onAdFailedToLoad";
        c2084g6.d = Integer.valueOf(i);
        s4.k(c2084g6);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void zzi() {
        long j = this.b.a;
        S4 s4 = this.a;
        C2084g6 c2084g6 = new C2084g6(DTBAdSize.AAX_INTERSTITIAL_AD_SIZE);
        c2084g6.a = Long.valueOf(j);
        c2084g6.c = "onAdLoaded";
        s4.k(c2084g6);
    }
}
