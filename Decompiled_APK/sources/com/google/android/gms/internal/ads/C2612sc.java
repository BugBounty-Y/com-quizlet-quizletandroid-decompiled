package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;

/* renamed from: com.google.android.gms.internal.ads.sc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2612sc extends AbstractC2771w5 {
    public final IBinder h4(com.google.android.gms.dynamic.b bVar, String str, BinderC2739va binderC2739va) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, bVar);
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, binderC2739va);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(1, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        parcelY3.recycle();
        return strongBinder;
    }
}
