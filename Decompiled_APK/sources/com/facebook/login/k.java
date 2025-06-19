package com.facebook.login;

import android.os.Parcel;
import android.os.Parcelable;
import com.facebook.login.DeviceAuthDialog;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        DeviceAuthDialog.RequestState requestState = new DeviceAuthDialog.RequestState();
        requestState.a = parcel.readString();
        requestState.b = parcel.readString();
        requestState.c = parcel.readString();
        requestState.d = parcel.readLong();
        requestState.e = parcel.readLong();
        return requestState;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new DeviceAuthDialog.RequestState[i];
    }
}
