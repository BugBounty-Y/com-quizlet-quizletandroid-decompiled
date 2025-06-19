package com.quizlet.ads.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.ads.data.AdDataType;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new AdDataType.CustomAdType(d.valueOf(parcel.readString()));
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new AdDataType.CustomAdType[i];
    }
}
