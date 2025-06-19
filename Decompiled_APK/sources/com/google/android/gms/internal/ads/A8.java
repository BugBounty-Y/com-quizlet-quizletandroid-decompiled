package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;

/* loaded from: classes2.dex */
public final class A8 extends AbstractC2771w5 implements C8 {
    public A8(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.formats.client.INativeAdViewDelegate", 0);
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final com.google.android.gms.dynamic.a C(String str) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        return assistantMode.refactored.a.h(Y3(2, parcelF3));
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final void D2(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(3, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final void K0(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(6, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final void V3(com.google.android.gms.dynamic.b bVar, int i) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, bVar);
        parcelF3.writeInt(i);
        d4(5, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final void Y2(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(7, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final void m2(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(9, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final void q1(InterfaceC2774w8 interfaceC2774w8) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, interfaceC2774w8);
        d4(8, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.C8
    public final void y2(com.google.android.gms.dynamic.a aVar, String str) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, aVar);
        d4(1, parcelF3);
    }
}
