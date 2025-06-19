package com.quizlet.quizletandroid.ui.setcreation.managers;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.generated.enums.O1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new CardFocusPosition(parcel.readInt(), parcel.readInt(), parcel.readInt() == 0 ? null : O1.valueOf(parcel.readString()));
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new CardFocusPosition[i];
    }
}
