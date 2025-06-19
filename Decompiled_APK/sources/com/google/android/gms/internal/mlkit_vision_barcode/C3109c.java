package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3109c extends AbstractC2771w5 implements InterfaceC3127e {
    public final C3100b h4(com.google.android.gms.dynamic.b bVar, zzah zzahVar) {
        C3100b c3100b;
        Parcel parcelF3 = f3();
        AbstractC3217o.a(parcelF3, bVar);
        parcelF3.writeInt(1);
        zzahVar.writeToParcel(parcelF3, 0);
        Parcel parcelP3 = p3(1, parcelF3);
        IBinder strongBinder = parcelP3.readStrongBinder();
        if (strongBinder == null) {
            c3100b = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.vision.barcode.internal.client.INativeBarcodeDetector");
            c3100b = iInterfaceQueryLocalInterface instanceof C3100b ? (C3100b) iInterfaceQueryLocalInterface : new C3100b(strongBinder, "com.google.android.gms.vision.barcode.internal.client.INativeBarcodeDetector", 5);
        }
        parcelP3.recycle();
        return c3100b;
    }
}
