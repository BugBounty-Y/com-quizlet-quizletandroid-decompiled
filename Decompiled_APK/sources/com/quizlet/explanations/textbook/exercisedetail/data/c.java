package com.quizlet.explanations.textbook.exercisedetail.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.explanations.textbook.exercisedetail.data.ExerciseDetailSetupState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new ExerciseDetailSetupState.Textbook(parcel.readString());
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ExerciseDetailSetupState.Textbook[i];
    }
}
