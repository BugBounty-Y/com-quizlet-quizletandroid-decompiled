package com.quizlet.features.questionnaire.navigation;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.features.questionnaire.navigation.Control;
import com.quizlet.features.questionnaire.navigation.StepModel;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new StepModel.SchoolCourse(parcel.readString(), Progress.CREATOR.createFromParcel(parcel), Control.Button.CREATOR.createFromParcel(parcel));
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new StepModel.SchoolCourse[i];
    }
}
