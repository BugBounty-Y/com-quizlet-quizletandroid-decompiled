package com.google.mlkit.vision.documentscanner;

import android.os.Parcel;
import android.os.Parcelable;

/* loaded from: classes2.dex */
final class zzg extends zzb {
    public static final Parcelable.Creator<zzg> CREATOR = new d();

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeParcelable(this.a, i);
    }
}
