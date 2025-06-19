package com.google.mlkit.vision.documentscanner;

import android.os.Parcel;
import android.os.Parcelable;

/* loaded from: classes2.dex */
final class zze extends zza {
    public static final Parcelable.Creator<zze> CREATOR = new c();

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeList(this.a);
        parcel.writeParcelable(this.b, i);
    }
}
