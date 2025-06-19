package com.quizlet.login.recovery.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.login.recovery.data.ScreenState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new ScreenState.KnownAccountExists(parcel.readString(), parcel.readString(), parcel.readString(), parcel.readInt() != 0);
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ScreenState.KnownAccountExists[i];
    }
}
