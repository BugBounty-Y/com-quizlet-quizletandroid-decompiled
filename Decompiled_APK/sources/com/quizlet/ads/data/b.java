package com.quizlet.ads.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.ads.data.AdDataType;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        parcel.readInt();
        return AdDataType.BannerAdType.b;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new AdDataType.BannerAdType[i];
    }
}
