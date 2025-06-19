package com.quizlet.explanations.feedback.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.explanations.feedback.data.ExplanationsFeedbackSetUpState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new ExplanationsFeedbackSetUpState.Exercise(parcel.readLong(), parcel.readString(), parcel.readString(), parcel.readString());
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ExplanationsFeedbackSetUpState.Exercise[i];
    }
}
