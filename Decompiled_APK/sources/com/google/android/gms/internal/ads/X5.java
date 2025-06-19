package com.google.android.gms.internal.ads;

import android.os.Parcel;

/* loaded from: classes2.dex */
public final class X5 extends AbstractC2771w5 implements Y5 {
    @Override // com.google.android.gms.internal.ads.Y5
    public final void X0(com.google.android.gms.dynamic.a aVar, InterfaceC1953d6 interfaceC1953d6) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.e(parcelF3, interfaceC1953d6);
        d4(4, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.Y5
    public final com.google.android.gms.ads.internal.client.s0 f() {
        Parcel parcelY3 = Y3(5, f3());
        com.google.android.gms.ads.internal.client.s0 s0VarE4 = Ug.e4(parcelY3.readStrongBinder());
        parcelY3.recycle();
        return s0VarE4;
    }
}
