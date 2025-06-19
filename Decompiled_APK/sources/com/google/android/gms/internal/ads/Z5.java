package com.google.android.gms.internal.ads;

import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class Z5 extends AbstractC2771w5 implements InterfaceC1866b6 {
    @Override // com.google.android.gms.internal.ads.InterfaceC1866b6
    public final void F(int i) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(i);
        d4(2, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1866b6
    public final void a0(zze zzeVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzeVar);
        d4(3, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1866b6
    public final void a4(Y5 y5) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, y5);
        d4(1, parcelF3);
    }
}
