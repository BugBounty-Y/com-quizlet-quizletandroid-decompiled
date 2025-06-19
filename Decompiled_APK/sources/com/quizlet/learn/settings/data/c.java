package com.quizlet.learn.settings.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        parcel.readInt();
        return WrittenQuestionGradingOption.Moderate.e;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new WrittenQuestionGradingOption.Moderate[i];
    }
}
