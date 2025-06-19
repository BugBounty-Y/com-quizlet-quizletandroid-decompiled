package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3100b extends AbstractC2771w5 {
    public final zzu[] h4(com.google.android.gms.dynamic.b bVar, zzan zzanVar) {
        Parcel parcelF3 = f3();
        AbstractC3217o.a(parcelF3, bVar);
        parcelF3.writeInt(1);
        zzanVar.writeToParcel(parcelF3, 0);
        Parcel parcelP3 = p3(1, parcelF3);
        zzu[] zzuVarArr = (zzu[]) parcelP3.createTypedArray(zzu.CREATOR);
        parcelP3.recycle();
        return zzuVarArr;
    }
}
