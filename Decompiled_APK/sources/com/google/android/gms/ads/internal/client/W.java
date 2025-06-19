package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.InterfaceC2825xa;

/* loaded from: classes2.dex */
public final class W extends AbstractC2771w5 implements Y {
    @Override // com.google.android.gms.ads.internal.client.Y
    public final InterfaceC2825xa getAdapterCreator() {
        Parcel parcelY3 = Y3(2, f3());
        InterfaceC2825xa interfaceC2825xaE4 = BinderC2739va.e4(parcelY3.readStrongBinder());
        parcelY3.recycle();
        return interfaceC2825xaE4;
    }

    @Override // com.google.android.gms.ads.internal.client.Y
    public final zzex getLiteSdkVersion() {
        Parcel parcelY3 = Y3(1, f3());
        zzex zzexVar = (zzex) AbstractC2857y5.a(parcelY3, zzex.CREATOR);
        parcelY3.recycle();
        return zzexVar;
    }
}
