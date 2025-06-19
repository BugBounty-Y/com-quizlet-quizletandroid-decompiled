package com.quizlet.quizletandroid.ui.activitycenter.views;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new ActivityCenterViewBindingHandler();
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ActivityCenterViewBindingHandler[i];
    }
}
