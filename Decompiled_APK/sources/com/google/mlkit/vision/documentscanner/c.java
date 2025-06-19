package com.google.mlkit.vision.documentscanner;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.mlkit.vision.documentscanner.GmsDocumentScanningResult;

/* loaded from: classes2.dex */
public final class c implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        return new zze(parcel.readArrayList(GmsDocumentScanningResult.class.getClassLoader()), (GmsDocumentScanningResult.Pdf) parcel.readParcelable(GmsDocumentScanningResult.class.getClassLoader()));
    }

    @Override // android.os.Parcelable.Creator
    public final /* synthetic */ Object[] newArray(int i) {
        return new zze[i];
    }
}
