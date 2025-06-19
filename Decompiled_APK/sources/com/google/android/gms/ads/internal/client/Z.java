package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.InterfaceC2825xa;
import com.google.android.gms.internal.ads.K9;
import com.google.android.gms.internal.ads.zzblu;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class Z extends AbstractC2771w5 implements InterfaceC1585b0 {
    public Z(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.client.IMobileAdsSettingManager", 0);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void F1(InterfaceC2825xa interfaceC2825xa) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, interfaceC2825xa);
        d4(11, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void M(String str) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        d4(18, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void N3(K9 k9) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, k9);
        d4(12, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final List h() {
        Parcel parcelY3 = Y3(13, f3());
        ArrayList arrayListCreateTypedArrayList = parcelY3.createTypedArrayList(zzblu.CREATOR);
        parcelY3.recycle();
        return arrayListCreateTypedArrayList;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void q3(com.google.android.gms.dynamic.a aVar, String str) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(null);
        AbstractC2857y5.e(parcelF3, aVar);
        d4(6, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void r0(zzfr zzfrVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzfrVar);
        d4(14, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void t() {
        d4(1, f3());
    }
}
