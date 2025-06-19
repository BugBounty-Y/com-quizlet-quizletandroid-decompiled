package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.Tc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1775Tc extends AbstractC2771w5 implements InterfaceC1787Vc {
    public C1775Tc(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.signals.ISignalGenerator", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1787Vc
    public final void K2(com.google.android.gms.dynamic.a aVar, zzbyz zzbyzVar, InterfaceC1769Sc interfaceC1769Sc) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzbyzVar);
        AbstractC2857y5.e(parcelF3, interfaceC1769Sc);
        d4(1, parcelF3);
    }
}
