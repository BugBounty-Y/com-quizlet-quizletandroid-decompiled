package com.quizlet.login.recovery.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.login.recovery.data.ScreenState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        parcel.readInt();
        return ScreenState.UnknownAccountExists.a;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ScreenState.UnknownAccountExists[i];
    }
}
