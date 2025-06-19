package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.InterfaceC2825xa;

/* loaded from: classes2.dex */
public final class L extends AbstractC2771w5 {
    public L(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.client.IAdManagerCreator", 0);
    }

    public final IBinder h4(com.google.android.gms.dynamic.b bVar, zzr zzrVar, String str, InterfaceC2825xa interfaceC2825xa, int i) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, bVar);
        AbstractC2857y5.c(parcelF3, zzrVar);
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, interfaceC2825xa);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        parcelF3.writeInt(i);
        Parcel parcelY3 = Y3(2, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        parcelY3.recycle();
        return strongBinder;
    }
}
