package com.google.android.gms.ads.internal.client;

/* loaded from: classes2.dex */
public final class H0 extends C {
    public final /* synthetic */ I0 a;

    public /* synthetic */ H0(I0 i0) {
        this.a = i0;
    }

    @Override // com.google.android.gms.ads.internal.client.D
    public final void B0(zzm zzmVar, int i) {
        com.google.android.gms.ads.internal.util.client.i.e("This app is using a lightweight version of the Google Mobile Ads SDK that requires the latest Google Play services to be installed, but Google Play services is either missing or out of date.");
        com.google.android.gms.ads.internal.util.client.c.b.post(new androidx.appcompat.app.J(this, 18));
    }

    @Override // com.google.android.gms.ads.internal.client.D
    public final void D0(zzm zzmVar) {
        B0(zzmVar, 1);
    }

    @Override // com.google.android.gms.ads.internal.client.D
    public final String f() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.D
    public final boolean f2() {
        return false;
    }

    @Override // com.google.android.gms.ads.internal.client.D
    public final String zze() {
        return null;
    }
}
