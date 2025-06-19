package com.quizlet.quizletandroid.ui.globalnav.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        parcel.readInt();
        return GlobalNavReroute.EdgyDataCollection.a;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new GlobalNavReroute.EdgyDataCollection[i];
    }
}
