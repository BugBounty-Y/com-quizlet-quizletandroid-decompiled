package com.quizlet.explanations.questiondetail.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.explanations.questiondetail.data.QuestionDetailSetUpState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class j implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new QuestionDetailSetUpState.WithId(parcel.readString());
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new QuestionDetailSetUpState.WithId[i];
    }
}
