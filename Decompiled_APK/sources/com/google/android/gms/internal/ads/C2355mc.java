package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zzm;

/* renamed from: com.google.android.gms.internal.ads.mc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2355mc extends AbstractC2771w5 implements InterfaceC2441oc {
    public C2355mc(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.rewarded.client.IRewardedAd", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final void C2(zzm zzmVar, InterfaceC2741vc interfaceC2741vc) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzmVar);
        AbstractC2857y5.e(parcelF3, interfaceC2741vc);
        d4(14, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final void D(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(5, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final void R0(InterfaceC2569rc interfaceC2569rc) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, interfaceC2569rc);
        d4(2, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final void Z2(zzm zzmVar, InterfaceC2741vc interfaceC2741vc) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzmVar);
        AbstractC2857y5.e(parcelF3, interfaceC2741vc);
        d4(1, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2441oc
    public final com.google.android.gms.ads.internal.client.s0 a() {
        Parcel parcelY3 = Y3(12, f3());
        com.google.android.gms.ads.internal.client.s0 s0VarE4 = Ug.e4(parcelY3.readStrongBinder());
        parcelY3.recycle();
        return s0VarE4;
    }
}
